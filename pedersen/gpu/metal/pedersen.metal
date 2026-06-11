// First-party Metal kernel for batched Pedersen vector commitments over
// BN254 G1.
//
// Computed quantity (M parallel commitments, each of size N):
//
//   C_m = sum_{i=0..N-1}  s[m][i] * G[i]   +   r[m] * H        for m = 0..M-1
//
// Two-stage pipeline (one metallib, two kernels):
//
//   1. pedersen_pointmul  --  M*(N+1) threads, one per (commitment, term).
//      Each thread does ONE scalar multiplication and writes the resulting
//      Jacobian point to a scratch buffer.
//
//   2. pedersen_reduce_add --  M threads, one per commitment. Each thread
//      sums (N+1) Jacobian points from scratch, then converts the result to
//      affine and writes it as 64-byte big-endian (32 BE for x, 32 BE for y).
//
// Byte-equality target: the Go canonical at
//   github.com/kinet-labs/crypto/pedersen
// (single-scalar case is the n=1 reduction; vector case matches the fixture
// generator at pedersen/test/tools/gen_pedersen_metal_kat.go.)
//
// Wire formats:
//
//   Generators G_basis (N points) + H (1 point)
//     ->  buffer of (N+1) * 64 bytes, raw big-endian (X || Y), gnark layout
//
//   Scalars S of shape [M][N]
//     ->  buffer of M*N*32 bytes, raw big-endian Fr (already reduced mod r)
//
//   Blindings r of shape [M]
//     ->  buffer of M*32 bytes, raw big-endian Fr (already reduced mod r)
//
//   Output commitments C of shape [M]
//     ->  buffer of M*64 bytes, raw big-endian (X || Y)

#include <metal_stdlib>
using namespace metal;

// =============================================================================
// BN254 base-field constants  (p = 21888242871839275222246405745257275088696...)
// =============================================================================

// p (4 limbs little-endian)
constant uint64_t BN254_P0 = 0x3C208C16D87CFD47ULL;
constant uint64_t BN254_P1 = 0x97816A916871CA8DULL;
constant uint64_t BN254_P2 = 0xB85045B68181585DULL;
constant uint64_t BN254_P3 = 0x30644E72E131A029ULL;

// R = 2^256 mod p   (Montgomery one)
constant uint64_t BN254_R_0 = 0xD35D438DC58F0D9DULL;
constant uint64_t BN254_R_1 = 0x0A78EB28F5C70B3DULL;
constant uint64_t BN254_R_2 = 0x666EA36F7879462CULL;
constant uint64_t BN254_R_3 = 0x0E0A77C19A07DF2FULL;

// R^2 mod p (used to enter Montgomery form: x_mont = montmul(x, R^2))
constant uint64_t BN254_R2_0 = 0xF32CFC5B538AFA89ULL;
constant uint64_t BN254_R2_1 = 0xB5E71911D44501FBULL;
constant uint64_t BN254_R2_2 = 0x47AB1EFF0A417FF6ULL;
constant uint64_t BN254_R2_3 = 0x06D89F71CAB8351FULL;

// -p^{-1} mod 2^64
constant uint64_t BN254_INV = 0x87D20782E4866389ULL;

// =============================================================================
// Plain 256-bit big integer helpers (used for I/O conversion + Montgomery mul)
// =============================================================================

struct U256 { uint64_t l[4]; };  // little-endian limbs

inline U256 u256_zero() {
    U256 x;
    x.l[0] = 0; x.l[1] = 0; x.l[2] = 0; x.l[3] = 0;
    return x;
}

inline bool u256_is_zero(thread const U256& a) {
    return (a.l[0] | a.l[1] | a.l[2] | a.l[3]) == 0;
}

inline bool u256_eq(thread const U256& a, thread const U256& b) {
    return a.l[0] == b.l[0] && a.l[1] == b.l[1] &&
           a.l[2] == b.l[2] && a.l[3] == b.l[3];
}

inline int u256_cmp_p(thread const U256& a) {
    if (a.l[3] != BN254_P3) return a.l[3] > BN254_P3 ? 1 : -1;
    if (a.l[2] != BN254_P2) return a.l[2] > BN254_P2 ? 1 : -1;
    if (a.l[1] != BN254_P1) return a.l[1] > BN254_P1 ? 1 : -1;
    if (a.l[0] != BN254_P0) return a.l[0] > BN254_P0 ? 1 : -1;
    return 0;
}

inline U256 fp_p() {
    U256 r; r.l[0]=BN254_P0; r.l[1]=BN254_P1; r.l[2]=BN254_P2; r.l[3]=BN254_P3;
    return r;
}

// Conditionally subtract p (single trial; result in [0, p)).
inline U256 fp_csub_p(thread const U256& a) {
    if (u256_cmp_p(a) < 0) return a;
    U256 r;
    uint64_t borrow = 0;
    uint64_t pl[4] = { BN254_P0, BN254_P1, BN254_P2, BN254_P3 };
    for (int i = 0; i < 4; ++i) {
        uint64_t ai = a.l[i];
        uint64_t s  = ai - pl[i] - borrow;
        // borrow if (a < b + borrow) -- careful unsigned underflow check
        borrow = ((ai < pl[i] + borrow) || (pl[i] + borrow < pl[i])) ? 1 : 0;
        r.l[i] = s;
    }
    return r;
}

// (a + b) mod p, inputs already < p (or sum < 2p which we then reduce).
inline U256 fp_add(thread const U256& a, thread const U256& b) {
    U256 r;
    uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t s = a.l[i] + b.l[i];
        uint64_t c1 = (s < a.l[i]) ? 1 : 0;
        uint64_t s2 = s + carry;
        uint64_t c2 = (s2 < s) ? 1 : 0;
        r.l[i] = s2;
        carry = c1 + c2;
    }
    return fp_csub_p(r);
}

// (a - b) mod p
inline U256 fp_sub(thread const U256& a, thread const U256& b) {
    U256 r;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t bi = b.l[i];
        uint64_t s = a.l[i] - bi - borrow;
        borrow = ((a.l[i] < bi + borrow) || (bi + borrow < bi)) ? 1 : 0;
        r.l[i] = s;
    }
    if (borrow) {
        // add p back
        uint64_t carry = 0;
        uint64_t pl[4] = { BN254_P0, BN254_P1, BN254_P2, BN254_P3 };
        for (int i = 0; i < 4; ++i) {
            uint64_t s = r.l[i] + pl[i];
            uint64_t c1 = (s < r.l[i]) ? 1 : 0;
            uint64_t s2 = s + carry;
            uint64_t c2 = (s2 < s) ? 1 : 0;
            r.l[i] = s2;
            carry = c1 + c2;
        }
    }
    return r;
}

inline U256 fp_neg(thread const U256& a) {
    if (u256_is_zero(a)) return a;
    U256 p = fp_p();
    return fp_sub(p, a);
}

// =============================================================================
// Schoolbook 256x256->512 + Montgomery reduction (CIOS)
// =============================================================================

// Add (lo, hi) into accumulator (acc_lo, acc_hi) with carry-out.
// Computes (acc_hi:acc_lo) = (acc_hi:acc_lo) + (hi:lo); returns carry-out (0 or 1).
inline uint64_t addc128(thread uint64_t& acc_lo, thread uint64_t& acc_hi,
                        uint64_t lo, uint64_t hi) {
    uint64_t a = acc_lo + lo;
    uint64_t c1 = (a < acc_lo) ? 1ULL : 0ULL;
    uint64_t b = acc_hi + hi;
    uint64_t c2 = (b < acc_hi) ? 1ULL : 0ULL;
    uint64_t b2 = b + c1;
    uint64_t c3 = (b2 < b) ? 1ULL : 0ULL;
    acc_lo = a;
    acc_hi = b2;
    return c2 + c3;
}

// Montgomery multiplication: returns a*b*R^{-1} mod p, where a,b are in
// Montgomery form (or general residues < p).  CIOS, 4-limb specialized.
inline U256 fp_mont_mul(thread const U256& a, thread const U256& b) {
    uint64_t pl[4] = { BN254_P0, BN254_P1, BN254_P2, BN254_P3 };

    // 5-limb accumulator + carry bit.
    uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;
    uint64_t t5 = 0;  // overflow guard (at most 1 across the loop)

    for (int i = 0; i < 4; ++i) {
        uint64_t ai = a.l[i];

        // Step A: t += a[i] * b
        {
            uint64_t carry = 0;
            uint64_t lo, hi;
            // j=0
            lo = ai * b.l[0]; hi = mulhi(ai, b.l[0]);
            uint64_t s = t0 + lo;
            uint64_t c1 = (s < t0) ? 1ULL : 0ULL;
            t0 = s;
            carry = hi + c1;
            // j=1
            lo = ai * b.l[1]; hi = mulhi(ai, b.l[1]);
            s = t1 + lo;
            c1 = (s < t1) ? 1ULL : 0ULL;
            uint64_t s2 = s + carry;
            uint64_t c2 = (s2 < s) ? 1ULL : 0ULL;
            t1 = s2;
            carry = hi + c1 + c2;
            // j=2
            lo = ai * b.l[2]; hi = mulhi(ai, b.l[2]);
            s = t2 + lo;
            c1 = (s < t2) ? 1ULL : 0ULL;
            s2 = s + carry;
            c2 = (s2 < s) ? 1ULL : 0ULL;
            t2 = s2;
            carry = hi + c1 + c2;
            // j=3
            lo = ai * b.l[3]; hi = mulhi(ai, b.l[3]);
            s = t3 + lo;
            c1 = (s < t3) ? 1ULL : 0ULL;
            s2 = s + carry;
            c2 = (s2 < s) ? 1ULL : 0ULL;
            t3 = s2;
            carry = hi + c1 + c2;
            // propagate into t4, t5
            s = t4 + carry;
            c1 = (s < t4) ? 1ULL : 0ULL;
            t4 = s;
            t5 = t5 + c1;
        }

        // Step B: m = t0 * INV mod 2^64; t = t + m*p; then shift down.
        uint64_t m = t0 * BN254_INV;
        {
            uint64_t carry = 0;
            uint64_t lo, hi;
            // j=0  (this zeroes out t0)
            lo = m * pl[0]; hi = mulhi(m, pl[0]);
            uint64_t s = t0 + lo;
            uint64_t c1 = (s < t0) ? 1ULL : 0ULL;
            // discard low result (it should equal 0 mod 2^64)
            carry = hi + c1;
            // j=1
            lo = m * pl[1]; hi = mulhi(m, pl[1]);
            s = t1 + lo;
            c1 = (s < t1) ? 1ULL : 0ULL;
            uint64_t s2 = s + carry;
            uint64_t c2 = (s2 < s) ? 1ULL : 0ULL;
            t1 = s2;
            carry = hi + c1 + c2;
            // j=2
            lo = m * pl[2]; hi = mulhi(m, pl[2]);
            s = t2 + lo;
            c1 = (s < t2) ? 1ULL : 0ULL;
            s2 = s + carry;
            c2 = (s2 < s) ? 1ULL : 0ULL;
            t2 = s2;
            carry = hi + c1 + c2;
            // j=3
            lo = m * pl[3]; hi = mulhi(m, pl[3]);
            s = t3 + lo;
            c1 = (s < t3) ? 1ULL : 0ULL;
            s2 = s + carry;
            c2 = (s2 < s) ? 1ULL : 0ULL;
            t3 = s2;
            carry = hi + c1 + c2;
            // propagate
            s = t4 + carry;
            c1 = (s < t4) ? 1ULL : 0ULL;
            t4 = s;
            t5 = t5 + c1;

            // shift down by one limb
            t0 = t1;
            t1 = t2;
            t2 = t3;
            t3 = t4;
            t4 = t5;
            t5 = 0;
        }
    }

    U256 r; r.l[0]=t0; r.l[1]=t1; r.l[2]=t2; r.l[3]=t3;
    if (t4 != 0) {
        // single-bit overflow: subtract p once.
        U256 p = fp_p();
        r = fp_sub(r, p);
    }
    return fp_csub_p(r);
}

inline U256 fp_mont_sqr(thread const U256& a) {
    return fp_mont_mul(a, a);
}

inline U256 fp_one_mont() {
    U256 r; r.l[0]=BN254_R_0; r.l[1]=BN254_R_1; r.l[2]=BN254_R_2; r.l[3]=BN254_R_3;
    return r;
}

inline U256 fp_r2() {
    U256 r; r.l[0]=BN254_R2_0; r.l[1]=BN254_R2_1; r.l[2]=BN254_R2_2; r.l[3]=BN254_R2_3;
    return r;
}

// Enter Montgomery form: returns x * R mod p (assumes x already < p).
inline U256 fp_to_mont(thread const U256& x) {
    return fp_mont_mul(x, fp_r2());
}

// Leave Montgomery form: returns x * R^{-1} mod p = montmul(x, 1).
inline U256 fp_from_mont(thread const U256& x) {
    U256 one;
    one.l[0]=1; one.l[1]=0; one.l[2]=0; one.l[3]=0;
    return fp_mont_mul(x, one);
}

// Inversion via Fermat's little theorem: a^(p-2) mod p.
// (No need for fast inversion -- only called M times per pipeline.)
inline U256 fp_inv(thread const U256& a) {
    // Exponent is p - 2.  Compute as repeated square-and-multiply with the
    // bit pattern of (p - 2) read MSB->LSB.  We unroll the bit loop on the
    // four limbs.  When a == 0, returns 0 (caller must guard).
    if (u256_is_zero(a)) return a;

    // p - 2 in 4 LE limbs:
    //   p0 - 2 (no borrow possible since p0 is large), p1, p2, p3
    uint64_t e0 = BN254_P0 - 2ULL;
    uint64_t e1 = BN254_P1;
    uint64_t e2 = BN254_P2;
    uint64_t e3 = BN254_P3;
    uint64_t exp[4] = { e0, e1, e2, e3 };

    U256 result = fp_one_mont();
    U256 base = a;
    // process bits LSB->MSB
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t e = exp[limb];
        for (int b = 0; b < 64; ++b) {
            if ((e >> b) & 1ULL) {
                result = fp_mont_mul(result, base);
            }
            base = fp_mont_sqr(base);
        }
    }
    return result;
}

// =============================================================================
// G1 in Jacobian coordinates (Montgomery form for X, Y, Z)
// =============================================================================

struct G1Jac {
    U256 X;
    U256 Y;
    U256 Z;  // Z == 0 represents point at infinity
};

struct G1Aff {
    U256 X;
    U256 Y;
    bool inf;
};

inline G1Jac g1_zero() {
    G1Jac p;
    p.X = fp_one_mont();
    p.Y = fp_one_mont();
    p.Z = u256_zero();
    return p;
}

inline bool g1_is_zero(thread const G1Jac& p) { return u256_is_zero(p.Z); }

// Doubling, BN254 a = 0 specialization (https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l)
inline G1Jac g1_dbl(thread const G1Jac& p) {
    if (g1_is_zero(p)) return p;
    U256 A = fp_mont_sqr(p.X);             // X^2
    U256 B = fp_mont_sqr(p.Y);             // Y^2
    U256 C = fp_mont_sqr(B);               // Y^4
    U256 t = fp_add(p.X, B);
    U256 t2 = fp_mont_sqr(t);              // (X+Y^2)^2
    U256 t3 = fp_sub(t2, A);
    U256 t4 = fp_sub(t3, C);
    U256 D = fp_add(t4, t4);               // 2*((X+Y^2)^2 - X^2 - Y^4)
    U256 E = fp_add(fp_add(A, A), A);      // 3*X^2
    U256 F = fp_mont_sqr(E);               // E^2
    G1Jac r;
    U256 twoD = fp_add(D, D);
    r.X = fp_sub(F, twoD);                 // F - 2D
    U256 D_minus_X = fp_sub(D, r.X);
    U256 EDX = fp_mont_mul(E, D_minus_X);
    U256 eightC = fp_add(C, C);
    eightC = fp_add(eightC, eightC);
    eightC = fp_add(eightC, eightC);       // 8*C
    r.Y = fp_sub(EDX, eightC);             // E*(D - X3) - 8*C
    U256 YZ = fp_mont_mul(p.Y, p.Z);
    r.Z = fp_add(YZ, YZ);                  // 2 Y Z
    return r;
}

// Mixed addition: Jacobian + Affine (Z2 = 1).  Standard formulas.
// Inputs in Montgomery form.  Returns Jacobian.
inline G1Jac g1_add_mixed(thread const G1Jac& p, thread const U256& Qx, thread const U256& Qy) {
    if (g1_is_zero(p)) {
        G1Jac r;
        r.X = Qx; r.Y = Qy; r.Z = fp_one_mont();
        return r;
    }
    U256 Z1Z1 = fp_mont_sqr(p.Z);                       // Z1^2
    U256 U2 = fp_mont_mul(Qx, Z1Z1);                    // U2 = X2*Z1^2
    U256 S2 = fp_mont_mul(Qy, fp_mont_mul(p.Z, Z1Z1));  // S2 = Y2*Z1^3
    U256 H = fp_sub(U2, p.X);                           // H = U2 - X1
    U256 r_v = fp_sub(S2, p.Y);                         // r = S2 - Y1
    if (u256_is_zero(H)) {
        if (u256_is_zero(r_v)) {
            return g1_dbl(p);
        }
        return g1_zero();
    }
    U256 HH = fp_mont_sqr(H);                           // H^2
    U256 I = fp_add(HH, HH);
    I = fp_add(I, I);                                   // 4*H^2
    U256 J = fp_mont_mul(H, I);                         // 4*H^3
    U256 r_2 = fp_add(r_v, r_v);                        // 2 r
    U256 V = fp_mont_mul(p.X, I);                       // X1 * 4 H^2
    G1Jac out;
    U256 r_sq = fp_mont_sqr(r_2);                       // (2r)^2
    U256 t1 = fp_sub(r_sq, J);
    U256 twoV = fp_add(V, V);
    out.X = fp_sub(t1, twoV);                           // X3 = r^2 - J - 2V
    U256 V_minus_X3 = fp_sub(V, out.X);
    U256 r_VX = fp_mont_mul(r_2, V_minus_X3);
    U256 Y1J = fp_mont_mul(p.Y, J);
    U256 twoY1J = fp_add(Y1J, Y1J);
    out.Y = fp_sub(r_VX, twoY1J);                       // Y3 = r*(V - X3) - 2 Y1 J
    out.Z = fp_mont_mul(p.Z, fp_add(H, H));             // Z3 = Z1 * 2H
    return out;
}

// Full Jacobian addition.  https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
inline G1Jac g1_add(thread const G1Jac& p, thread const G1Jac& q) {
    if (g1_is_zero(p)) return q;
    if (g1_is_zero(q)) return p;
    U256 Z1Z1 = fp_mont_sqr(p.Z);
    U256 Z2Z2 = fp_mont_sqr(q.Z);
    U256 U1 = fp_mont_mul(p.X, Z2Z2);
    U256 U2 = fp_mont_mul(q.X, Z1Z1);
    U256 S1 = fp_mont_mul(fp_mont_mul(p.Y, q.Z), Z2Z2);
    U256 S2 = fp_mont_mul(fp_mont_mul(q.Y, p.Z), Z1Z1);
    U256 H = fp_sub(U2, U1);
    U256 r_v = fp_sub(S2, S1);
    if (u256_is_zero(H)) {
        if (u256_is_zero(r_v)) return g1_dbl(p);
        return g1_zero();
    }
    U256 r2 = fp_add(r_v, r_v);
    U256 HH = fp_mont_sqr(H);
    U256 I = fp_add(HH, HH);
    I = fp_add(I, I);
    U256 J = fp_mont_mul(H, I);
    U256 V = fp_mont_mul(U1, I);
    G1Jac out;
    U256 r_sq = fp_mont_sqr(r2);
    U256 t1 = fp_sub(r_sq, J);
    U256 twoV = fp_add(V, V);
    out.X = fp_sub(t1, twoV);
    U256 V_minus_X3 = fp_sub(V, out.X);
    U256 r_VX = fp_mont_mul(r2, V_minus_X3);
    U256 S1J = fp_mont_mul(S1, J);
    U256 twoS1J = fp_add(S1J, S1J);
    out.Y = fp_sub(r_VX, twoS1J);
    U256 Z1Z2 = fp_mont_mul(p.Z, q.Z);
    out.Z = fp_mont_mul(Z1Z2, fp_add(H, H));
    return out;
}

// Convert Jacobian -> Affine.  Returns inf=true iff Z == 0.
inline G1Aff g1_to_affine(thread const G1Jac& p) {
    G1Aff r;
    if (g1_is_zero(p)) {
        r.X = u256_zero(); r.Y = u256_zero(); r.inf = true;
        return r;
    }
    U256 Zinv = fp_inv(p.Z);
    U256 Zinv2 = fp_mont_sqr(Zinv);
    U256 Zinv3 = fp_mont_mul(Zinv2, Zinv);
    r.X = fp_mont_mul(p.X, Zinv2);
    r.Y = fp_mont_mul(p.Y, Zinv3);
    r.inf = false;
    return r;
}

// Scalar multiplication: standard left-to-right binary ladder.
// `s` is provided as four little-endian 64-bit limbs in NON-Montgomery form
// (raw integer).  Affine input (Q in Montgomery form, no Z).  Returns Jacobian.
inline G1Jac g1_scalar_mul_aff(thread const U256& Qx, thread const U256& Qy,
                                thread const uint64_t s[4]) {
    G1Jac acc = g1_zero();
    // top limb first (MSB)
    for (int li = 3; li >= 0; --li) {
        uint64_t limb = s[li];
        for (int bi = 63; bi >= 0; --bi) {
            acc = g1_dbl(acc);
            if ((limb >> bi) & 1ULL) {
                acc = g1_add_mixed(acc, Qx, Qy);
            }
        }
    }
    return acc;
}

// =============================================================================
// I/O: raw 32-byte big-endian Fp <-> Montgomery U256
// =============================================================================

// Read 32-byte BE -> 4 LE limbs (no reduction; assumes value already < p or < r).
inline U256 read_be32(device const uint8_t* p) {
    U256 r;
    for (int limb = 0; limb < 4; ++limb) {
        // limb 0 = least significant 8 bytes; in BE these are the LAST 8 bytes
        const device uint8_t* src = p + (3 - limb) * 8;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v = (v << 8) | (uint64_t)src[i];
        }
        r.l[limb] = v;
    }
    return r;
}

// Write 4 LE limbs -> 32-byte BE.
inline void write_be32(device uint8_t* p, thread const U256& a) {
    for (int limb = 0; limb < 4; ++limb) {
        device uint8_t* dst = p + (3 - limb) * 8;
        uint64_t v = a.l[limb];
        for (int i = 7; i >= 0; --i) {
            dst[i] = (uint8_t)(v & 0xFFu);
            v >>= 8;
        }
    }
}

// =============================================================================
// Kernel 1: pedersen_pointmul   --   one thread per (m, i) scalar mul
// =============================================================================
//
// Layout:
//   tid = m * (N + 1) + i                 (i in [0, N+1))
//
//   For i in [0, N):
//       point  = G_basis[i]               (raw BE 64 bytes)
//       scalar = S[m*N + i]               (raw BE 32 bytes)
//
//   For i == N:
//       point  = H                        (raw BE 64 bytes)
//       scalar = blinding[m]              (raw BE 32 bytes)
//
// Output:
//   scratch[tid]  =  scalar * point       in Jacobian Montgomery form (3*32 bytes)
//
// We write the full Jacobian (X, Y, Z) into scratch as 96 bytes per term.
// Reduction in kernel 2 reads them back.

struct PedersenDims {
    uint32_t M;     // number of commitments
    uint32_t N;     // basis size
};

kernel void pedersen_pointmul(
    device const uint8_t*      gens_be   [[buffer(0)]],   // (N+1)*64 BE bytes
    device const uint8_t*      scalars_be [[buffer(1)]],  // M*N*32 BE bytes
    device const uint8_t*      blindings_be [[buffer(2)]],// M*32 BE bytes
    device       uint64_t*     scratch    [[buffer(3)]],  // M*(N+1)*12 u64 (X||Y||Z)
    constant   PedersenDims&   dims       [[buffer(4)]],
    uint                       tid       [[thread_position_in_grid]]
) {
    uint32_t M = dims.M;
    uint32_t N = dims.N;
    uint32_t total = M * (N + 1);
    if (tid >= total) return;

    uint32_t m = tid / (N + 1);
    uint32_t i = tid - m * (N + 1);

    // Pick generator and scalar
    U256 Qx_raw, Qy_raw, scalar_raw;
    if (i < N) {
        Qx_raw = read_be32(gens_be + i * 64);
        Qy_raw = read_be32(gens_be + i * 64 + 32);
        scalar_raw = read_be32(scalars_be + (m * N + i) * 32);
    } else {
        Qx_raw = read_be32(gens_be + N * 64);
        Qy_raw = read_be32(gens_be + N * 64 + 32);
        scalar_raw = read_be32(blindings_be + m * 32);
    }

    // Convert generator coords to Montgomery form (X, Y < p assumed).
    U256 Qx = fp_to_mont(Qx_raw);
    U256 Qy = fp_to_mont(Qy_raw);

    // scalar limbs (raw integer, NOT Montgomery)
    uint64_t s[4] = { scalar_raw.l[0], scalar_raw.l[1], scalar_raw.l[2], scalar_raw.l[3] };

    G1Jac result = g1_scalar_mul_aff(Qx, Qy, s);

    // Write Jacobian (X, Y, Z) Montgomery limbs into scratch.
    uint32_t base = tid * 12;
    for (int k = 0; k < 4; ++k) scratch[base + 0 + k] = result.X.l[k];
    for (int k = 0; k < 4; ++k) scratch[base + 4 + k] = result.Y.l[k];
    for (int k = 0; k < 4; ++k) scratch[base + 8 + k] = result.Z.l[k];
}

// =============================================================================
// Kernel 2: pedersen_reduce_add  --  one thread per commitment; sums (N+1) terms
// =============================================================================

inline G1Jac scratch_load(device const uint64_t* scratch, uint32_t idx) {
    G1Jac r;
    uint32_t base = idx * 12;
    for (int k = 0; k < 4; ++k) r.X.l[k] = scratch[base + 0 + k];
    for (int k = 0; k < 4; ++k) r.Y.l[k] = scratch[base + 4 + k];
    for (int k = 0; k < 4; ++k) r.Z.l[k] = scratch[base + 8 + k];
    return r;
}

kernel void pedersen_reduce_add(
    device const uint64_t*   scratch     [[buffer(0)]],   // M*(N+1)*12 u64
    device       uint8_t*    out_be      [[buffer(1)]],   // M*64 BE bytes
    constant   PedersenDims& dims        [[buffer(2)]],
    uint                     m           [[thread_position_in_grid]]
) {
    uint32_t M = dims.M;
    uint32_t N = dims.N;
    if (m >= M) return;

    uint32_t base = m * (N + 1);
    G1Jac acc = g1_zero();
    for (uint32_t i = 0; i < N + 1; ++i) {
        G1Jac term = scratch_load(scratch, base + i);
        if (g1_is_zero(term)) continue;
        acc = g1_add(acc, term);
    }

    // Convert to affine and emit raw BE.
    G1Aff aff = g1_to_affine(acc);
    if (aff.inf) {
        // Emit (0, 0) BE for infinity (matches gnark's encoding when point is identity).
        device uint8_t* dst = out_be + m * 64;
        for (int b = 0; b < 64; ++b) dst[b] = 0;
        return;
    }
    // Convert from Montgomery before BE emit.
    U256 X_raw = fp_from_mont(aff.X);
    U256 Y_raw = fp_from_mont(aff.Y);
    write_be32(out_be + m * 64,        X_raw);
    write_be32(out_be + m * 64 + 32,   Y_raw);
}

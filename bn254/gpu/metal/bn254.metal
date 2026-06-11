// =============================================================================
// BN254 (alt_bn128) Metal Compute Shaders
// =============================================================================
//
// GPU-accelerated elliptic curve operations for BN254 on Apple Silicon.
// Used for Pedersen commitments, PLONK verification, and Groth16 proofs.
//
// BN254 Parameters:
//   p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
//   r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//   G1: y^2 = x^3 + 3  over Fp
//
// References:
//   - EIP-196, EIP-197 (Ethereum precompiles)
//   - Zcash BN-254 specification
//

#include <metal_stdlib>
using namespace metal;

// =============================================================================
// 256-bit Field Arithmetic (4 x 64-bit limbs)
// =============================================================================

// BN254 base field prime p (4 limbs, little-endian)
constant uint64_t BN254_P[4] = {
    0x3C208C16D87CFD47,
    0x97816A916871CA8D,
    0xB85045B68181585D,
    0x30644E72E131A029
};

// p - 2 used for Fermat inversion: z^{-1} = z^{p-2} mod p.
// p_minus_2 = p - 2 (4 limbs, little-endian).
constant uint64_t BN254_P_MINUS_2[4] = {
    0x3C208C16D87CFD45,  // 0x3C208C16D87CFD47 - 2
    0x97816A916871CA8D,
    0xB85045B68181585D,
    0x30644E72E131A029
};

// Montgomery R^2 mod p
constant uint64_t BN254_R2[4] = {
    0xF32CFC5B538AFA89,
    0xB5E71911D44501FB,
    0x47AB1EFF0A417FF6,
    0x06D89F71CAB8351F
};

// Montgomery constant: -p^{-1} mod 2^64
constant uint64_t BN254_INV = 0x87D20782E4866389;

// Generator points (Montgomery form)
constant uint64_t BN254_G1_X[4] = {
    0xD35D438DC58F0D9D,
    0x0A78EB28F5C70B3D,
    0x666EA36F7879462C,
    0x0E0A77C19A07DF2F
};

constant uint64_t BN254_G1_Y[4] = {
    0xA6BA871B8B1E1B3A,
    0x14F1D651EB8E167B,
    0xCCDD46DEF0F28C58,
    0x1C14EF83340FBE5E
};

// Fp256 represented as 4 uint64 limbs
struct Fp256 {
    uint64_t limbs[4];
};

// G1 affine point
struct G1Affine {
    Fp256 x;
    Fp256 y;
    bool infinity;
};

// G1 projective point (Jacobian coordinates)
struct G1Projective {
    Fp256 x;
    Fp256 y;
    Fp256 z;
};

// =============================================================================
// Multi-precision Arithmetic
// =============================================================================

inline uint64_t adc(uint64_t a, uint64_t b, thread uint64_t& carry) {
    uint64_t result = a + carry;
    carry = (result < a) ? 1 : 0;
    uint64_t sum = result + b;
    carry += (sum < result) ? 1 : 0;
    return sum;
}

inline uint64_t sbb(uint64_t a, uint64_t b, thread uint64_t& borrow) {
    uint64_t diff = a - borrow;
    borrow = (a < borrow) ? 1 : 0;
    uint64_t result = diff - b;
    borrow += (diff < b) ? 1 : 0;
    return result;
}

inline void mul64(uint64_t a, uint64_t b, thread uint64_t& lo, thread uint64_t& hi) {
    lo = a * b;
    hi = mulhi(a, b);
}

inline int fp256_cmp(thread const Fp256& a, constant uint64_t* b) {
    for (int i = 3; i >= 0; i--) {
        if (a.limbs[i] < b[i]) return -1;
        if (a.limbs[i] > b[i]) return 1;
    }
    return 0;
}

// =============================================================================
// Field Operations
// =============================================================================

inline Fp256 fp256_zero() {
    Fp256 r;
    for (int i = 0; i < 4; i++) r.limbs[i] = 0;
    return r;
}

inline Fp256 fp256_one() {
    // R mod p (Montgomery form of 1)
    Fp256 r;
    r.limbs[0] = 0x4E6E0206CA34BB1E;
    r.limbs[1] = 0x7E2F6A58BE66A5E7;
    r.limbs[2] = 0x30C1B89EB0E1C70D;
    r.limbs[3] = 0x2AE3C0E97F5A0A1D;
    return r;
}

inline bool fp256_is_zero(thread const Fp256& a) {
    return a.limbs[0] == 0 && a.limbs[1] == 0 && a.limbs[2] == 0 && a.limbs[3] == 0;
}

inline void fp256_reduce(thread Fp256& a) {
    if (fp256_cmp(a, BN254_P) >= 0) {
        uint64_t borrow = 0;
        for (int i = 0; i < 4; i++) {
            a.limbs[i] = sbb(a.limbs[i], BN254_P[i], borrow);
        }
    }
}

inline Fp256 fp256_add(thread const Fp256& a, thread const Fp256& b) {
    Fp256 c;
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        c.limbs[i] = adc(a.limbs[i], b.limbs[i], carry);
    }
    fp256_reduce(c);
    return c;
}

inline Fp256 fp256_sub(thread const Fp256& a, thread const Fp256& b) {
    Fp256 c;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        c.limbs[i] = sbb(a.limbs[i], b.limbs[i], borrow);
    }
    if (borrow) {
        uint64_t carry = 0;
        for (int i = 0; i < 4; i++) {
            c.limbs[i] = adc(c.limbs[i], BN254_P[i], carry);
        }
    }
    return c;
}

inline Fp256 fp256_neg(thread const Fp256& a) {
    if (fp256_is_zero(a)) return a;
    Fp256 c;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        c.limbs[i] = sbb(BN254_P[i], a.limbs[i], borrow);
    }
    return c;
}

// Montgomery multiplication
inline Fp256 fp256_mont_mul(thread const Fp256& a, thread const Fp256& b) {
    uint64_t t[8] = {0};

    // Schoolbook multiplication
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            uint64_t lo, hi;
            mul64(a.limbs[i], b.limbs[j], lo, hi);
            uint64_t sum = t[i+j] + lo + carry;
            carry = (sum < t[i+j]) ? 1 : 0;
            carry += hi;
            t[i+j] = sum;
        }
        t[i+4] = carry;
    }

    // Montgomery reduction
    for (int i = 0; i < 4; i++) {
        uint64_t k = t[i] * BN254_INV;
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            uint64_t lo, hi;
            mul64(k, BN254_P[j], lo, hi);
            uint64_t sum = t[i+j] + lo + carry;
            carry = (sum < t[i+j]) ? 1 : 0;
            carry += hi;
            t[i+j] = sum;
        }
        // Propagate carry
        for (int j = i + 4; j < 8; j++) {
            uint64_t sum = t[j] + carry;
            carry = (sum < t[j]) ? 1 : 0;
            t[j] = sum;
            if (carry == 0) break;
        }
    }

    Fp256 c;
    for (int i = 0; i < 4; i++) {
        c.limbs[i] = t[i + 4];
    }
    fp256_reduce(c);
    return c;
}

inline Fp256 fp256_square(thread const Fp256& a) {
    return fp256_mont_mul(a, a);
}

inline Fp256 fp256_double(thread const Fp256& a) {
    return fp256_add(a, a);
}

// Fermat's little theorem inversion: z^{-1} = z^{p-2} mod p.
// Square-and-multiply over the bits of (p-2) LSB->MSB.  The exponent is
// public + fixed, so we always perform 256 squarings + ~120 conditional
// multiplies.  Sufficient for ZK fixed-exponent inversion on the GPU.
inline Fp256 fp256_inverse(thread const Fp256& z) {
    Fp256 result = fp256_one();
    Fp256 base = z;
    for (int i = 0; i < 4; i++) {
        uint64_t e = BN254_P_MINUS_2[i];
        for (int j = 0; j < 64; j++) {
            if ((e >> j) & 1ULL) {
                result = fp256_mont_mul(result, base);
            }
            base = fp256_square(base);
        }
    }
    return result;
}

// =============================================================================
// G1 Point Operations
// =============================================================================

inline G1Affine g1_identity() {
    G1Affine p;
    p.x = fp256_zero();
    p.y = fp256_zero();
    p.infinity = true;
    return p;
}

inline G1Projective g1_to_projective(thread const G1Affine& p) {
    G1Projective r;
    r.x = p.x;
    r.y = p.y;
    r.z = p.infinity ? fp256_zero() : fp256_one();
    return r;
}

// Constant-time conditional move on G1 projective points.
// dst = mask ? src : dst, where mask is 0 (keep dst) or all-ones (take src).
// Mirrors banderwagon::pt_cmov so both metal kernels share the same idiom.
inline void pt_cmov(thread G1Projective& dst, thread const G1Projective& src, uint64_t mask) {
    for (int i = 0; i < 4; i++) {
        dst.x.limbs[i] = (dst.x.limbs[i] & ~mask) | (src.x.limbs[i] & mask);
        dst.y.limbs[i] = (dst.y.limbs[i] & ~mask) | (src.y.limbs[i] & mask);
        dst.z.limbs[i] = (dst.z.limbs[i] & ~mask) | (src.z.limbs[i] & mask);
    }
}

// Constant-time conditional move on G1 affine points (including infinity flag).
// dst = mask ? src : dst, where mask is 0 (keep dst) or all-ones (take src).
inline void pt_cmov_affine(thread G1Affine& dst, thread const G1Affine& src, uint64_t mask) {
    for (int i = 0; i < 4; i++) {
        dst.x.limbs[i] = (dst.x.limbs[i] & ~mask) | (src.x.limbs[i] & mask);
        dst.y.limbs[i] = (dst.y.limbs[i] & ~mask) | (src.y.limbs[i] & mask);
    }
    bool take_src = (mask != 0ULL);
    dst.infinity = take_src ? src.infinity : dst.infinity;
}

// Branchless Jacobian -> affine. Always performs the inversion + Mont muls so
// timing does not leak whether the input was the point at infinity. The
// is-infinity case is selected via pt_cmov_affine after the unconditional work.
inline G1Affine g1_to_affine(thread const G1Projective& p) {
    // Unconditionally compute affine candidate. fp256_inverse(0) yields a
    // garbage field element; we discard it via cmov below, so it never reaches
    // the caller.
    Fp256 z_inv  = fp256_inverse(p.z);
    Fp256 z_inv2 = fp256_square(z_inv);
    Fp256 z_inv3 = fp256_mont_mul(z_inv2, z_inv);

    G1Affine candidate;
    candidate.x = fp256_mont_mul(p.x, z_inv2);
    candidate.y = fp256_mont_mul(p.y, z_inv3);
    candidate.infinity = false;

    // Identity selector: mask = 0xFFFF...FFFF if p.z == 0 else 0.
    uint64_t z_zero = (uint64_t)(0ULL - (uint64_t)fp256_is_zero(p.z));

    G1Affine result = candidate;
    G1Affine identity = g1_identity();
    pt_cmov_affine(result, identity, z_zero);
    return result;
}

// Branchless point doubling. Always evaluates the Jacobian doubling formulas
// then cmoves the projective identity in if the input was the point at
// infinity. Eliminates the secret-dependent branch on p.z.
inline G1Projective g1_double(thread const G1Projective& p) {
    // Using Jacobian doubling formulas (computed unconditionally)
    Fp256 a = fp256_square(p.x);                    // a = X^2
    Fp256 b = fp256_square(p.y);                    // b = Y^2
    Fp256 c = fp256_square(b);                      // c = Y^4

    Fp256 xb = fp256_add(p.x, b);
    Fp256 d = fp256_sub(fp256_square(xb), fp256_add(a, c));
    d = fp256_double(d);                            // d = 2*((X+Y^2)^2 - X^2 - Y^4)

    Fp256 e = fp256_add(fp256_double(a), a);        // e = 3*X^2
    Fp256 f = fp256_square(e);                      // f = (3*X^2)^2

    G1Projective dbl;
    dbl.x = fp256_sub(f, fp256_double(d));          // X' = f - 2*d
    dbl.y = fp256_sub(fp256_mont_mul(e, fp256_sub(d, dbl.x)),
                     fp256_double(fp256_double(fp256_double(c)))); // Y' = e*(d-X') - 8*c
    dbl.z = fp256_double(fp256_mont_mul(p.y, p.z)); // Z' = 2*Y*Z

    // If p.z == 0 (input was the point at infinity), return the projective
    // identity. cmov makes the dispatch constant-time.
    uint64_t z_zero = (uint64_t)(0ULL - (uint64_t)fp256_is_zero(p.z));
    G1Projective result = dbl;
    pt_cmov(result, p, z_zero);
    return result;
}

// Point addition in Jacobian coordinates -- branchless version.
// All conditional cases (P+0, 0+Q, P+P, P+(-P)) are computed unconditionally
// then selected via pt_cmov so the dispatch is constant-time and the GPU
// path is byte-equal to the CPU oracle for every input.
inline G1Projective g1_add(thread const G1Projective& p, thread const G1Projective& q) {
    Fp256 z1z1 = fp256_square(p.z);                              // Z1^2
    Fp256 z2z2 = fp256_square(q.z);                              // Z2^2
    Fp256 u1 = fp256_mont_mul(p.x, z2z2);                        // U1 = X1*Z2^2
    Fp256 u2 = fp256_mont_mul(q.x, z1z1);                        // U2 = X2*Z1^2
    Fp256 s1 = fp256_mont_mul(fp256_mont_mul(p.y, q.z), z2z2);   // S1 = Y1*Z2^3
    Fp256 s2 = fp256_mont_mul(fp256_mont_mul(q.y, p.z), z1z1);   // S2 = Y2*Z1^3

    Fp256 h = fp256_sub(u2, u1);                                 // H = U2 - U1
    Fp256 r_val = fp256_sub(s2, s1);                             // r = S2 - S1

    Fp256 hh = fp256_square(h);                                  // H^2
    Fp256 hhh = fp256_mont_mul(h, hh);                           // H^3
    Fp256 v = fp256_mont_mul(u1, hh);                            // V = U1*H^2

    G1Projective add_result;
    add_result.x = fp256_sub(fp256_sub(fp256_square(r_val), hhh), fp256_double(v));
    add_result.y = fp256_sub(fp256_mont_mul(r_val, fp256_sub(v, add_result.x)),
                             fp256_mont_mul(s1, hhh));
    add_result.z = fp256_mont_mul(fp256_mont_mul(p.z, q.z), h);

    G1Projective dbl_result = g1_double(p);

    G1Projective inf;
    inf.x = fp256_one();
    inf.y = fp256_one();
    inf.z = fp256_zero();

    // Selectors. mask = 0xFFFF...FFFF if condition true else 0.
    uint64_t p_zero  = (uint64_t)(0ULL - (uint64_t)fp256_is_zero(p.z));
    uint64_t q_zero  = (uint64_t)(0ULL - (uint64_t)fp256_is_zero(q.z));
    uint64_t h_zero  = (uint64_t)(0ULL - (uint64_t)fp256_is_zero(h));
    uint64_t r_zero  = (uint64_t)(0ULL - (uint64_t)fp256_is_zero(r_val));

    G1Projective out = add_result;
    pt_cmov(out, dbl_result, h_zero & r_zero);    // P+P -> doubling
    pt_cmov(out, inf,        h_zero & ~r_zero);   // P+(-P) -> infinity
    pt_cmov(out, q,          p_zero);             // 0+Q -> Q
    pt_cmov(out, p,          q_zero);             // P+0 -> P
    return out;
}

// Constant-time scalar multiplication (Jacobian).
// Mirrors banderwagon::pt_scalar_mul (banderwagon.metal:319-333):
//   * iterate LSB->MSB across the 4-limb scalar (256 bits)
//   * at each bit: compute acc + base unconditionally, cmov-select via mask
//   * always double the base
// Eliminates the secret-dependent `if (bit)` branch and yields output
// byte-equal to the CPU oracle.
inline G1Projective g1_scalar_mul(thread const G1Affine& p, thread const uint64_t scalar[4]) {
    G1Projective acc;
    acc.x = fp256_one();
    acc.y = fp256_one();
    acc.z = fp256_zero(); // identity

    G1Projective base = g1_to_projective(p);

    for (int i = 0; i < 4; i++) {
        uint64_t limb = scalar[i];
        for (int j = 0; j < 64; j++) {
            uint64_t bit  = (limb >> j) & 1ULL;
            uint64_t mask = 0ULL - bit;
            G1Projective sum = g1_add(acc, base);
            pt_cmov(acc, sum, mask);
            base = g1_double(base);
        }
    }
    return acc;
}

// =============================================================================
// Pedersen Commitment Kernel
// =============================================================================

// Pedersen commitment kernel.
//
// ABI (changed 2026-04-28, LP-137-ORG-LAYOUT B3 fix):
//   buffer(0)  values       : per-commitment scalar value v (4 limbs each, Mont form)
//   buffer(1)  blinding     : per-commitment scalar blinding r (4 limbs each, Mont form)
//   buffer(2)  G_xy         : 8 limbs of generator G (x||y), Mont form, supplied by host
//   buffer(3)  H_xy         : 8 limbs of generator H (x||y), Mont form, supplied by host
//   buffer(4)  commitments  : output (8 limbs each: x||y)
//   buffer(5)  num_commitments
//
// Host MUST derive G,H independently via bn254 hash-to-curve with brand-neutral
// DSTs ("KINET_PEDERSEN_G", "KINET_PEDERSEN_H") so the on-curve generators have no
// known discrete-log relation. The previous `Hp = g1_double(Gp)` was discrete-
// log-revealing (H = 2G) and broke the hiding property of the commitment.
kernel void pedersen_commit(
    device const uint64_t* values      [[buffer(0)]],
    device const uint64_t* blinding    [[buffer(1)]],
    device const uint64_t* G_xy        [[buffer(2)]],
    device const uint64_t* H_xy        [[buffer(3)]],
    device uint64_t*       commitments [[buffer(4)]],
    constant uint32_t&     num_commitments [[buffer(5)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= num_commitments) return;

    uint64_t v[4], r[4];
    for (int i = 0; i < 4; i++) {
        v[i] = values[index * 4 + i];
        r[i] = blinding[index * 4 + i];
    }

    // Load host-supplied generators G and H (Mont form, x||y).
    G1Affine G;
    G1Affine H;
    for (int i = 0; i < 4; i++) {
        G.x.limbs[i] = G_xy[i];
        G.y.limbs[i] = G_xy[4 + i];
        H.x.limbs[i] = H_xy[i];
        H.y.limbs[i] = H_xy[4 + i];
    }
    G.infinity = false;
    H.infinity = false;

    // C = v*G + r*H using the constant-time ladder.
    G1Projective vG = g1_scalar_mul(G, v);
    G1Projective rH = g1_scalar_mul(H, r);
    G1Projective C  = g1_add(vG, rH);
    G1Affine C_affine = g1_to_affine(C);

    uint32_t out_offset = index * 8;
    for (int i = 0; i < 4; i++) {
        commitments[out_offset + i]     = C_affine.x.limbs[i];
        commitments[out_offset + 4 + i] = C_affine.y.limbs[i];
    }
}

// =============================================================================
// Batch Point Addition Kernel
// =============================================================================

kernel void bn254_batch_add(
    device const uint64_t* points_a [[buffer(0)]],    // Input points A (8 limbs each)
    device const uint64_t* points_b [[buffer(1)]],    // Input points B (8 limbs each)
    device uint64_t* results [[buffer(2)]],           // Output points (8 limbs each)
    constant uint32_t& num_points [[buffer(3)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= num_points) return;

    uint32_t offset = index * 8;

    // Load points
    G1Affine a, b;
    for (int i = 0; i < 4; i++) {
        a.x.limbs[i] = points_a[offset + i];
        a.y.limbs[i] = points_a[offset + 4 + i];
        b.x.limbs[i] = points_b[offset + i];
        b.y.limbs[i] = points_b[offset + 4 + i];
    }
    a.infinity = false;
    b.infinity = false;

    // Add points
    G1Projective ap = g1_to_projective(a);
    G1Projective bp = g1_to_projective(b);
    G1Projective sum = g1_add(ap, bp);
    G1Affine result = g1_to_affine(sum);

    // Output
    for (int i = 0; i < 4; i++) {
        results[offset + i] = result.x.limbs[i];
        results[offset + 4 + i] = result.y.limbs[i];
    }
}

// =============================================================================
// Batch Scalar Multiplication Kernel (MSM - Multi-Scalar Multiplication)
// =============================================================================

kernel void bn254_batch_scalar_mul(
    device const uint64_t* points [[buffer(0)]],      // Base points (8 limbs each)
    device const uint64_t* scalars [[buffer(1)]],     // Scalars (4 limbs each)
    device uint64_t* results [[buffer(2)]],           // Output points (8 limbs each)
    constant uint32_t& num_points [[buffer(3)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= num_points) return;

    // Load point and scalar
    G1Affine p;
    uint64_t s[4];
    uint32_t p_offset = index * 8;
    uint32_t s_offset = index * 4;

    for (int i = 0; i < 4; i++) {
        p.x.limbs[i] = points[p_offset + i];
        p.y.limbs[i] = points[p_offset + 4 + i];
        s[i] = scalars[s_offset + i];
    }
    p.infinity = false;

    // Scalar multiplication
    G1Projective result = g1_scalar_mul(p, s);
    G1Affine result_affine = g1_to_affine(result);

    // Output
    for (int i = 0; i < 4; i++) {
        results[p_offset + i] = result_affine.x.limbs[i];
        results[p_offset + 4 + i] = result_affine.y.limbs[i];
    }
}

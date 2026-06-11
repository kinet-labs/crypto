// First-party Metal kernel for Poseidon2-BN254 (canonical default permutation).
//
// Byte-equal to kinet::crypto::poseidon::hash2 in poseidon/cpp/poseidon.cpp,
// which mirrors gnark-crypto v0.20.1 ecc/bn254/fr/poseidon2 with parameters
// (t=2, rF=6, rP=50, d=5). The round-key constant table is emitted by the
// CPU body itself via dump_round_keys -> gen_metal_constants and #include'd
// here, so there is exactly one source of truth for round constants.
//
// Constant-time: the permutation has no data-dependent branches; the only
// branches are the canonical reductions in field arithmetic, which depend
// purely on internal carries and match the CPU body bit-for-bit.

#include <metal_stdlib>
using namespace metal;

#include "poseidon2_bn254_rk.metalh"  // POSEIDON2_RK[56][2][4] (Montgomery limbs)

// =============================================================================
// BN254 Fr modulus q (4x64 little-endian limbs).
//   q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
// Montgomery params: qInvNeg = -q^{-1} mod 2^64; rSquare = R^2 mod q.
// All values match poseidon/cpp/poseidon.cpp byte-for-byte.
// =============================================================================
constant ulong Q0 = 0x43e1f593f0000001UL;
constant ulong Q1 = 0x2833e84879b97091UL;
constant ulong Q2 = 0xb85045b68181585dUL;
constant ulong Q3 = 0x30644e72e131a029UL;
constant ulong Q_INV_NEG = 0xc2e1f593efffffffUL;

constant ulong R_SQUARE_0 = 1997599621687373223UL;
constant ulong R_SQUARE_1 = 6052339484930628067UL;
constant ulong R_SQUARE_2 = 10108755138030829701UL;
constant ulong R_SQUARE_3 = 150537098327114917UL;

// =============================================================================
// 256-bit field element in Montgomery form.
// =============================================================================
struct Fr {
    ulong l0, l1, l2, l3;
};

// =============================================================================
// Multi-precision primitives. mul64 uses Metal's native mulhi(u64,u64) which
// emits the hardware-accelerated high-multiply instruction on Apple silicon.
// adc/sbb keep the carry-flag pattern that mirrors the CPU body exactly.
// =============================================================================

inline void mul64(ulong a, ulong b, thread ulong &lo, thread ulong &hi) {
    lo = a * b;
    hi = mulhi(a, b);
}

inline ulong adc(ulong a, ulong b, thread ulong &carry) {
    ulong s = a + b;
    ulong c1 = (s < a) ? 1UL : 0UL;
    ulong s2 = s + carry;
    ulong c2 = (s2 < s) ? 1UL : 0UL;
    carry = c1 + c2;
    return s2;
}

inline ulong sbb(ulong a, ulong b, thread ulong &borrow) {
    ulong d = a - b;
    ulong b1 = (a < b) ? 1UL : 0UL;
    ulong d2 = d - borrow;
    ulong b2 = (d < borrow) ? 1UL : 0UL;
    borrow = b1 + b2;
    return d2;
}

// cmp_q: returns -1 if a<q, 0 if a==q, 1 if a>q. Matches CPU body.
inline int cmp_q(thread const Fr &a) {
    if (a.l3 != Q3) return (a.l3 < Q3) ? -1 : 1;
    if (a.l2 != Q2) return (a.l2 < Q2) ? -1 : 1;
    if (a.l1 != Q1) return (a.l1 < Q1) ? -1 : 1;
    if (a.l0 != Q0) return (a.l0 < Q0) ? -1 : 1;
    return 0;
}

// reduce_once: subtract q if a >= q. Used after operations that produce
// values in [0, 2q).
inline void reduce_once(thread Fr &a) {
    if (cmp_q(a) >= 0) {
        ulong br = 0;
        a.l0 = sbb(a.l0, Q0, br);
        a.l1 = sbb(a.l1, Q1, br);
        a.l2 = sbb(a.l2, Q2, br);
        a.l3 = sbb(a.l3, Q3, br);
    }
}

// fr_add: c = a + b mod q. Identical to poseidon/cpp/poseidon.cpp::fr_add.
inline Fr fr_add(thread const Fr &a, thread const Fr &b) {
    Fr c;
    ulong cy = 0;
    c.l0 = adc(a.l0, b.l0, cy);
    c.l1 = adc(a.l1, b.l1, cy);
    c.l2 = adc(a.l2, b.l2, cy);
    c.l3 = adc(a.l3, b.l3, cy);
    if (cy != 0 || cmp_q(c) >= 0) {
        ulong br = 0;
        c.l0 = sbb(c.l0, Q0, br);
        c.l1 = sbb(c.l1, Q1, br);
        c.l2 = sbb(c.l2, Q2, br);
        c.l3 = sbb(c.l3, Q3, br);
    }
    return c;
}

inline Fr fr_double(thread const Fr &a) { return fr_add(a, a); }

// fr_mul: Montgomery multiplication, CIOS layout. c = a * b * R^{-1} mod q.
// Identical algorithm to poseidon/cpp/poseidon.cpp::fr_mul.
inline Fr fr_mul(thread const Fr &a, thread const Fr &b) {
    ulong t[5] = {0, 0, 0, 0, 0};
    const ulong al[4] = {a.l0, a.l1, a.l2, a.l3};
    const ulong bl[4] = {b.l0, b.l1, b.l2, b.l3};
    const ulong qq[4] = {Q0, Q1, Q2, Q3};

    for (int i = 0; i < 4; ++i) {
        // t += a * b[i]
        ulong cy = 0;
        for (int j = 0; j < 4; ++j) {
            ulong lo, hi;
            mul64(al[j], bl[i], lo, hi);
            ulong s = t[j] + lo;
            ulong c1 = (s < t[j]) ? 1UL : 0UL;
            ulong s2 = s + cy;
            ulong c2 = (s2 < s) ? 1UL : 0UL;
            t[j] = s2;
            cy = hi + c1 + c2;
        }
        t[4] += cy;

        // m = t[0] * qInvNeg mod 2^64
        ulong m = t[0] * Q_INV_NEG;

        // t += m * q
        cy = 0;
        for (int j = 0; j < 4; ++j) {
            ulong lo, hi;
            mul64(m, qq[j], lo, hi);
            ulong s = t[j] + lo;
            ulong c1 = (s < t[j]) ? 1UL : 0UL;
            ulong s2 = s + cy;
            ulong c2 = (s2 < s) ? 1UL : 0UL;
            t[j] = s2;
            cy = hi + c1 + c2;
        }
        t[4] += cy;

        // t[0] is now zero; shift right by one limb.
        t[0] = t[1];
        t[1] = t[2];
        t[2] = t[3];
        t[3] = t[4];
        t[4] = 0;
    }
    Fr c;
    c.l0 = t[0]; c.l1 = t[1]; c.l2 = t[2]; c.l3 = t[3];
    reduce_once(c);
    return c;
}

inline Fr fr_square(thread const Fr &a) { return fr_mul(a, a); }

// =============================================================================
// Poseidon2-BN254 default permutation (t=2, rF=6 split 3+3, rP=50, d=5).
//   sBox: x -> x^5 = ((x^2)^2) * x
//   matMulExternal (t=2, M_E = circ(2,1)):
//       tmp = s0+s1; s0 += tmp; s1 += tmp.
//   matMulInternal (t=2, M_I = [[2,1],[1,3]]):
//       sum = s0+s1; s0 += sum; s1 = 2*s1 + sum.
// =============================================================================

inline void sbox(thread Fr &x) {
    Fr x2 = fr_square(x);
    Fr x4 = fr_square(x2);
    x = fr_mul(x4, x);
}

inline void mat_mul_external(thread Fr s[2]) {
    Fr tmp = fr_add(s[0], s[1]);
    s[0] = fr_add(s[0], tmp);
    s[1] = fr_add(s[1], tmp);
}

inline void mat_mul_internal(thread Fr s[2]) {
    Fr sum = fr_add(s[0], s[1]);
    s[0] = fr_add(s[0], sum);
    Fr s1d = fr_double(s[1]);
    s[1] = fr_add(s1d, sum);
}

// Round-key indices in POSEIDON2_RK (matches dump_round_keys order):
//   [0..2]   full pre-rounds  -> 3 rounds, 2 keys each
//   [3..52]  partial rounds   -> 50 rounds, 1 key each (slot 1 ignored)
//   [53..55] full post-rounds -> 3 rounds, 2 keys each
constant int FULL_HALF = 3;
constant int PARTIAL  = 50;

inline Fr load_rk(int round, int slot) {
    Fr r;
    r.l0 = POSEIDON2_RK[round][slot][0];
    r.l1 = POSEIDON2_RK[round][slot][1];
    r.l2 = POSEIDON2_RK[round][slot][2];
    r.l3 = POSEIDON2_RK[round][slot][3];
    return r;
}

inline void permute(thread Fr s[2]) {
    // Initial external matrix mix (gnark applies M_E once before the first
    // full round; the CPU body matches).
    mat_mul_external(s);

    // Full pre-rounds.
    for (int i = 0; i < FULL_HALF; ++i) {
        Fr k0 = load_rk(i, 0);
        Fr k1 = load_rk(i, 1);
        s[0] = fr_add(s[0], k0);
        s[1] = fr_add(s[1], k1);
        sbox(s[0]);
        sbox(s[1]);
        mat_mul_external(s);
    }

    // Partial rounds.
    for (int i = 0; i < PARTIAL; ++i) {
        Fr k0 = load_rk(FULL_HALF + i, 0);
        s[0] = fr_add(s[0], k0);
        sbox(s[0]);
        mat_mul_internal(s);
    }

    // Full post-rounds.
    for (int i = 0; i < FULL_HALF; ++i) {
        Fr k0 = load_rk(FULL_HALF + PARTIAL + i, 0);
        Fr k1 = load_rk(FULL_HALF + PARTIAL + i, 1);
        s[0] = fr_add(s[0], k0);
        s[1] = fr_add(s[1], k1);
        sbox(s[0]);
        sbox(s[1]);
        mat_mul_external(s);
    }
}

// =============================================================================
// Bytes (BE) <-> Fr (Montgomery LE limbs) conversions.
// gnark-crypto's SetBytes treats the 32-byte input as a big-endian integer,
// then reduces modulo q (BN254 q > 2^253, so input < 2^256 needs at most 4
// subtractions in the worst case but typically 0 or 1) and converts to
// Montgomery by multiplying by R^2.
// =============================================================================

inline Fr be_to_fr_mont(device const uchar *be) {
    auto rd = [&](int off) -> ulong {
        ulong v = 0;
        for (int b = 0; b < 8; ++b) {
            v = (v << 8) | (ulong)be[off + b];
        }
        return v;
    };
    Fr x;
    x.l0 = rd(24);
    x.l1 = rd(16);
    x.l2 = rd(8);
    x.l3 = rd(0);
    // Bring into [0, q) by subtracting q until smaller. Bounded loop (<= 4).
    for (int i = 0; i < 4; ++i) {
        if (cmp_q(x) < 0) break;
        ulong br = 0;
        x.l0 = sbb(x.l0, Q0, br);
        x.l1 = sbb(x.l1, Q1, br);
        x.l2 = sbb(x.l2, Q2, br);
        x.l3 = sbb(x.l3, Q3, br);
    }
    Fr r2;
    r2.l0 = R_SQUARE_0; r2.l1 = R_SQUARE_1;
    r2.l2 = R_SQUARE_2; r2.l3 = R_SQUARE_3;
    return fr_mul(x, r2);
}

inline void fr_mont_to_be(thread const Fr &x, device uchar *be) {
    // from_mont: multiply Montgomery value by 1 in regular form (= R^{-1}).
    Fr one_reg;
    one_reg.l0 = 1; one_reg.l1 = 0; one_reg.l2 = 0; one_reg.l3 = 0;
    Fr r = fr_mul(x, one_reg);
    ulong limbs[4] = {r.l0, r.l1, r.l2, r.l3};
    // Big-endian 32-byte output: limb 3 first.
    for (int i = 0; i < 4; ++i) {
        ulong v = limbs[i];
        int off = 32 - 8 * (i + 1);
        for (int b = 7; b >= 0; --b) {
            be[off + b] = (uchar)(v & 0xff);
            v >>= 8;
        }
    }
}

// =============================================================================
// Kernel: poseidon2_hash2_batch.
// Inputs:  pairs[i] = 64 bytes = [BE(left) | BE(right)].
// Output:  outs[i]  = 32 bytes BE.
// One thread per pair.
// =============================================================================
kernel void poseidon2_hash2_batch(
    device const uchar  *pairs [[buffer(0)]],   // n * 64 bytes
    device uchar        *outs  [[buffer(1)]],   // n * 32 bytes
    constant uint       &n     [[buffer(2)]],
    uint i [[thread_position_in_grid]])
{
    if (i >= n) return;

    Fr s[2];
    s[0] = be_to_fr_mont(pairs + i * 64);
    s[1] = be_to_fr_mont(pairs + i * 64 + 32);
    Fr saved_right = s[1];

    permute(s);

    // gnark-crypto Compress: out = saved_right + s[1].
    Fr out = fr_add(saved_right, s[1]);
    fr_mont_to_be(out, outs + i * 32);
}

// WGSL driver for Poseidon2-BN254 -- C++ host polyfill of the WGSL kernel.
//
// Mirrors poseidon/gpu/wgsl/poseidon2_bn254.wgsl byte-for-byte: each 64-bit
// Montgomery limb is represented as a (lo, hi) pair of uint32_t, and every
// 64-bit op is reconstructed from u32 primitives. This is exactly what WGSL
// does; running the same arithmetic on the host gives byte-equal output to
// both the WGSL kernel and the CPU oracle.
//
// The round-key constants live in poseidon2_bn254_rk.wgslh (auto-generated
// from the CPU body), which exposes both POSEIDON2_RK_LO/HI on __cplusplus
// and on the WGSL side. Single source of truth.

#include "poseidon2_driver.h"
#include "poseidon2_bn254_rk.wgslh"

#include <cstdint>
#include <cstring>

namespace {

// =============================================================================
// 64-bit unsigned as (lo, hi) of u32. Matches WGSL `struct U64`.
// =============================================================================
struct U64 { uint32_t lo, hi; };

inline U64 u64_make(uint32_t lo, uint32_t hi) { return U64{lo, hi}; }
inline U64 u64_zero() { return U64{0u, 0u}; }
inline bool u64_lt(U64 a, U64 b) {
    if (a.hi != b.hi) return a.hi < b.hi;
    return a.lo < b.lo;
}
inline bool u64_eq(U64 a, U64 b) { return a.lo == b.lo && a.hi == b.hi; }

struct U64Carry { U64 v; uint32_t carry; };
struct U64Borrow { U64 v; uint32_t borrow; };

inline U64Carry u64_add_carry(U64 a, U64 b, uint32_t cin) {
    uint32_t lo1 = a.lo + b.lo;
    uint32_t c0  = (lo1 < a.lo) ? 1u : 0u;
    uint32_t lo  = lo1 + cin;
    uint32_t c1  = (lo  < lo1) ? 1u : 0u;
    uint32_t hi1 = a.hi + b.hi;
    uint32_t c2  = (hi1 < a.hi) ? 1u : 0u;
    uint32_t hi2 = hi1 + (c0 + c1);
    uint32_t c3  = (hi2 < hi1) ? 1u : 0u;
    return U64Carry{U64{lo, hi2}, c2 + c3};
}

inline U64Borrow u64_sub_borrow(U64 a, U64 b, uint32_t bin) {
    uint32_t lo1 = a.lo - b.lo;
    uint32_t bor0 = (a.lo < b.lo) ? 1u : 0u;
    uint32_t lo   = lo1 - bin;
    uint32_t bor1 = (lo1 < bin)   ? 1u : 0u;
    uint32_t hi1  = a.hi - b.hi;
    uint32_t bor2 = (a.hi < b.hi) ? 1u : 0u;
    uint32_t bor_in_hi = bor0 + bor1;
    uint32_t hi   = hi1 - bor_in_hi;
    uint32_t bor3 = (hi1 < bor_in_hi) ? 1u : 0u;
    return U64Borrow{U64{lo, hi}, bor2 + bor3};
}

// 32x32 -> 64 multiply, decomposed via 16-bit halves so no intermediate
// product exceeds u32. This is the byte-equivalent of WGSL's
// u64_make_from_u32_mul.
inline U64 u32_mul(uint32_t a, uint32_t b) {
    uint32_t al = a & 0xffffu;
    uint32_t ah = a >> 16;
    uint32_t bl = b & 0xffffu;
    uint32_t bh = b >> 16;
    uint32_t ll = al * bl;
    uint32_t lh = al * bh;
    uint32_t hl = ah * bl;
    uint32_t hh = ah * bh;
    uint32_t mid_a = (ll >> 16) + (lh & 0xffffu);
    uint32_t mid_b = mid_a + (hl & 0xffffu);
    uint32_t mid_carry = (mid_b >> 16);
    uint32_t lo = (ll & 0xffffu) | (mid_b << 16);
    uint32_t hi = hh + (lh >> 16) + (hl >> 16) + mid_carry;
    return U64{lo, hi};
}

struct U128 { uint32_t l0, l1, l2, l3; };

inline U128 umul64(U64 a, U64 b) {
    U64 p_ll = u32_mul(a.lo, b.lo);
    U64 p_lh = u32_mul(a.lo, b.hi);
    U64 p_hl = u32_mul(a.hi, b.lo);
    U64 p_hh = u32_mul(a.hi, b.hi);
    uint32_t w0 = p_ll.lo;
    uint32_t s1a = p_ll.hi + p_lh.lo;
    uint32_t c1a = (s1a < p_ll.hi) ? 1u : 0u;
    uint32_t w1  = s1a + p_hl.lo;
    uint32_t c1b = (w1  < s1a)     ? 1u : 0u;
    uint32_t carry1 = c1a + c1b;
    uint32_t s2a = p_lh.hi + p_hl.hi;
    uint32_t c2a = (s2a < p_lh.hi) ? 1u : 0u;
    uint32_t s2b = s2a + p_hh.lo;
    uint32_t c2b = (s2b < s2a)     ? 1u : 0u;
    uint32_t w2  = s2b + carry1;
    uint32_t c2c = (w2  < s2b)     ? 1u : 0u;
    uint32_t carry2 = c2a + c2b + c2c;
    uint32_t w3  = p_hh.hi + carry2;
    return U128{w0, w1, w2, w3};
}

// Low 64 bits of u64 * u64, used for the Montgomery m = t[0]*qInvNeg.
inline U64 u64_mul_low(U64 a, U64 b) {
    U64 p_ll = u32_mul(a.lo, b.lo);
    U64 p_lh = u32_mul(a.lo, b.hi);
    U64 p_hl = u32_mul(a.hi, b.lo);
    uint32_t lo = p_ll.lo;
    uint32_t hi = p_ll.hi + p_lh.lo + p_hl.lo;
    return U64{lo, hi};
}

// =============================================================================
// BN254 Fr modulus + Montgomery params. Same numeric values as the kernel
// constants (declared as u32 lo/hi pairs).
// =============================================================================
constexpr U64 Q0_U = U64{0xf0000001u, 0x43e1f593u};
constexpr U64 Q1_U = U64{0x79b97091u, 0x2833e848u};
constexpr U64 Q2_U = U64{0x8181585du, 0xb85045b6u};
constexpr U64 Q3_U = U64{0xe131a029u, 0x30644e72u};
constexpr U64 QINV = U64{0xefffffffu, 0xc2e1f593u};

constexpr U64 R2_0 = U64{0xae216da7u, 0x1bb8e645u};
constexpr U64 R2_1 = U64{0xe35c59e3u, 0x53fe3ab1u};
constexpr U64 R2_2 = U64{0x53bb8085u, 0x8c49833du};
constexpr U64 R2_3 = U64{0x7f4e44a5u, 0x0216d0b1u};

struct Fr {
    U64 l0, l1, l2, l3;
};

inline Fr fr_zero() { return Fr{u64_zero(), u64_zero(), u64_zero(), u64_zero()}; }
inline Fr fr_q()    { return Fr{Q0_U, Q1_U, Q2_U, Q3_U}; }
inline Fr fr_r2()   { return Fr{R2_0, R2_1, R2_2, R2_3}; }

inline int cmp_q(const Fr &a) {
    Fr q = fr_q();
    if (!u64_eq(a.l3, q.l3)) return u64_lt(a.l3, q.l3) ? -1 : 1;
    if (!u64_eq(a.l2, q.l2)) return u64_lt(a.l2, q.l2) ? -1 : 1;
    if (!u64_eq(a.l1, q.l1)) return u64_lt(a.l1, q.l1) ? -1 : 1;
    if (!u64_eq(a.l0, q.l0)) return u64_lt(a.l0, q.l0) ? -1 : 1;
    return 0;
}

inline Fr fr_sub_q(const Fr &a) {
    Fr q = fr_q();
    auto r0 = u64_sub_borrow(a.l0, q.l0, 0u);
    auto r1 = u64_sub_borrow(a.l1, q.l1, r0.borrow);
    auto r2 = u64_sub_borrow(a.l2, q.l2, r1.borrow);
    auto r3 = u64_sub_borrow(a.l3, q.l3, r2.borrow);
    return Fr{r0.v, r1.v, r2.v, r3.v};
}

inline Fr reduce_once(const Fr &a) {
    return cmp_q(a) >= 0 ? fr_sub_q(a) : a;
}

inline Fr fr_add(const Fr &a, const Fr &b) {
    auto r0 = u64_add_carry(a.l0, b.l0, 0u);
    auto r1 = u64_add_carry(a.l1, b.l1, r0.carry);
    auto r2 = u64_add_carry(a.l2, b.l2, r1.carry);
    auto r3 = u64_add_carry(a.l3, b.l3, r2.carry);
    Fr c{r0.v, r1.v, r2.v, r3.v};
    if (r3.carry != 0u || cmp_q(c) >= 0) c = fr_sub_q(c);
    return c;
}

inline Fr fr_double(const Fr &a) { return fr_add(a, a); }

// CIOS Montgomery multiplication, u32-only.
inline Fr fr_mul(const Fr &a, const Fr &b) {
    U64 t[5] = {u64_zero(), u64_zero(), u64_zero(), u64_zero(), u64_zero()};
    const U64 al[4] = {a.l0, a.l1, a.l2, a.l3};
    const U64 bl[4] = {b.l0, b.l1, b.l2, b.l3};
    const U64 qq[4] = {Q0_U, Q1_U, Q2_U, Q3_U};

    for (int i = 0; i < 4; ++i) {
        U64 cy = u64_zero();
        for (int j = 0; j < 4; ++j) {
            U128 prod = umul64(al[j], bl[i]);
            U64 lo = U64{prod.l0, prod.l1};
            U64 hi = U64{prod.l2, prod.l3};
            auto s  = u64_add_carry(t[j], lo, 0u);
            auto s2 = u64_add_carry(s.v,  cy, 0u);
            t[j] = s2.v;
            // cy = hi + s.carry + s2.carry
            auto cy1 = u64_add_carry(hi,    U64{s.carry,  0u}, 0u);
            auto cy2 = u64_add_carry(cy1.v, U64{s2.carry, 0u}, 0u);
            cy = cy2.v;
        }
        auto t4u = u64_add_carry(t[4], cy, 0u);
        t[4] = t4u.v;

        U64 m = u64_mul_low(t[0], QINV);

        cy = u64_zero();
        for (int j = 0; j < 4; ++j) {
            U128 prod = umul64(m, qq[j]);
            U64 lo = U64{prod.l0, prod.l1};
            U64 hi = U64{prod.l2, prod.l3};
            auto s  = u64_add_carry(t[j], lo, 0u);
            auto s2 = u64_add_carry(s.v,  cy, 0u);
            t[j] = s2.v;
            auto cy1 = u64_add_carry(hi,    U64{s.carry,  0u}, 0u);
            auto cy2 = u64_add_carry(cy1.v, U64{s2.carry, 0u}, 0u);
            cy = cy2.v;
        }
        auto t4u2 = u64_add_carry(t[4], cy, 0u);
        t[4] = t4u2.v;

        t[0] = t[1];
        t[1] = t[2];
        t[2] = t[3];
        t[3] = t[4];
        t[4] = u64_zero();
    }
    Fr c{t[0], t[1], t[2], t[3]};
    return reduce_once(c);
}

inline Fr fr_square(const Fr &a) { return fr_mul(a, a); }

inline Fr sbox(const Fr &x) {
    Fr x2 = fr_square(x);
    Fr x4 = fr_square(x2);
    return fr_mul(x4, x);
}

struct State2 { Fr s0, s1; };

inline State2 mat_mul_external(const State2 &s) {
    Fr tmp = fr_add(s.s0, s.s1);
    return State2{fr_add(s.s0, tmp), fr_add(s.s1, tmp)};
}
inline State2 mat_mul_internal(const State2 &s) {
    Fr sum = fr_add(s.s0, s.s1);
    Fr s0p = fr_add(s.s0, sum);
    Fr s1d = fr_double(s.s1);
    Fr s1p = fr_add(s1d, sum);
    return State2{s0p, s1p};
}

constexpr int FULL_HALF = 3;
constexpr int PARTIAL   = 50;

inline Fr load_rk(int round, int slot) {
    return Fr{
        U64{POSEIDON2_RK_LO[round][slot][0], POSEIDON2_RK_HI[round][slot][0]},
        U64{POSEIDON2_RK_LO[round][slot][1], POSEIDON2_RK_HI[round][slot][1]},
        U64{POSEIDON2_RK_LO[round][slot][2], POSEIDON2_RK_HI[round][slot][2]},
        U64{POSEIDON2_RK_LO[round][slot][3], POSEIDON2_RK_HI[round][slot][3]}
    };
}

inline State2 permute(const State2 &s_in) {
    State2 s = mat_mul_external(s_in);
    for (int i = 0; i < FULL_HALF; ++i) {
        Fr k0 = load_rk(i, 0);
        Fr k1 = load_rk(i, 1);
        s.s0 = fr_add(s.s0, k0);
        s.s1 = fr_add(s.s1, k1);
        s.s0 = sbox(s.s0);
        s.s1 = sbox(s.s1);
        s = mat_mul_external(s);
    }
    for (int i = 0; i < PARTIAL; ++i) {
        Fr k0 = load_rk(FULL_HALF + i, 0);
        s.s0 = fr_add(s.s0, k0);
        s.s0 = sbox(s.s0);
        s = mat_mul_internal(s);
    }
    for (int i = 0; i < FULL_HALF; ++i) {
        Fr k0 = load_rk(FULL_HALF + PARTIAL + i, 0);
        Fr k1 = load_rk(FULL_HALF + PARTIAL + i, 1);
        s.s0 = fr_add(s.s0, k0);
        s.s1 = fr_add(s.s1, k1);
        s.s0 = sbox(s.s0);
        s.s1 = sbox(s.s1);
        s = mat_mul_external(s);
    }
    return s;
}

inline U64 read_be64(const unsigned char *p) {
    uint32_t hi = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                  ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
    uint32_t lo = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                  ((uint32_t)p[6] <<  8) |  (uint32_t)p[7];
    return U64{lo, hi};
}

inline void write_be64(unsigned char *p, U64 v) {
    p[0] = (unsigned char)(v.hi >> 24);
    p[1] = (unsigned char)(v.hi >> 16);
    p[2] = (unsigned char)(v.hi >>  8);
    p[3] = (unsigned char)(v.hi      );
    p[4] = (unsigned char)(v.lo >> 24);
    p[5] = (unsigned char)(v.lo >> 16);
    p[6] = (unsigned char)(v.lo >>  8);
    p[7] = (unsigned char)(v.lo      );
}

inline Fr be_to_fr_mont(const unsigned char *be) {
    Fr x{
        read_be64(be + 24),
        read_be64(be + 16),
        read_be64(be +  8),
        read_be64(be +  0)
    };
    for (int i = 0; i < 4; ++i) {
        if (cmp_q(x) < 0) break;
        x = fr_sub_q(x);
    }
    return fr_mul(x, fr_r2());
}

inline void fr_mont_to_be(unsigned char *be, const Fr &x) {
    Fr one_reg{U64{1u, 0u}, u64_zero(), u64_zero(), u64_zero()};
    Fr r = fr_mul(x, one_reg);
    write_be64(be +  0, r.l3);
    write_be64(be +  8, r.l2);
    write_be64(be + 16, r.l1);
    write_be64(be + 24, r.l0);
}

}  // namespace

extern "C" int poseidon2_hash2_wgsl_batch(const unsigned char *pairs,
                                          unsigned char       *outs,
                                          unsigned long        n) {
    if (n == 0) return 0;
    if (!pairs || !outs) return -1;
    for (unsigned long i = 0; i < n; ++i) {
        State2 s{
            be_to_fr_mont(pairs + i * 64),
            be_to_fr_mont(pairs + i * 64 + 32)
        };
        Fr saved_right = s.s1;
        s = permute(s);
        Fr digest = fr_add(saved_right, s.s1);
        fr_mont_to_be(outs + i * 32, digest);
    }
    return 0;
}

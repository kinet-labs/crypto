// SPDX-License-Identifier: Apache-2.0
//
// banderwagon/fp.cpp -- Bandersnatch base field arithmetic.
// First-party. No vendoring. See fp.hpp for the contract.

#include "fp.hpp"

#include <cstring>

namespace kinet::banderwagon {

// Modulus q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
constexpr std::uint64_t Q0 = 0xffffffff00000001ULL;
constexpr std::uint64_t Q1 = 0x53bda402fffe5bfeULL;
constexpr std::uint64_t Q2 = 0x3339d80809a1d805ULL;
constexpr std::uint64_t Q3 = 0x73eda753299d7d48ULL;

// q' such that q * q' = -1 mod 2^64  (i.e. -q^{-1} mod 2^64).
constexpr std::uint64_t QINV_NEG = 0xfffffffeffffffffULL;

// R^2 mod q  (R = 2^256). Used to convert into Montgomery form.
constexpr std::uint64_t R2_0 = 0xc999e990f3f29c6dULL;
constexpr std::uint64_t R2_1 = 0x2b6cedcb87925c23ULL;
constexpr std::uint64_t R2_2 = 0x05d314967254398fULL;
constexpr std::uint64_t R2_3 = 0x0748d9d99f59ff11ULL;

// R mod q (this *is* the Montgomery representation of 1).
constexpr std::uint64_t R0 = 0x00000001fffffffeULL;
constexpr std::uint64_t R1 = 0x5884b7fa00034802ULL;
constexpr std::uint64_t R2 = 0x998c4fefecbc4ff5ULL;
constexpr std::uint64_t R3 = 0x1824b159acc5056fULL;

namespace {

// 64x64 -> 128 multiply, returning (hi, lo).
inline void mul_u64(std::uint64_t a, std::uint64_t b,
                    std::uint64_t& hi, std::uint64_t& lo) {
    const __uint128_t p = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b);
    lo = static_cast<std::uint64_t>(p);
    hi = static_cast<std::uint64_t>(p >> 64);
}

// Add with carry: returns sum, sets carry_out.
inline std::uint64_t adc(std::uint64_t a, std::uint64_t b,
                         std::uint64_t carry_in, std::uint64_t& carry_out) {
    const __uint128_t s = static_cast<__uint128_t>(a) +
                          static_cast<__uint128_t>(b) +
                          static_cast<__uint128_t>(carry_in);
    carry_out = static_cast<std::uint64_t>(s >> 64);
    return static_cast<std::uint64_t>(s);
}

// Subtract with borrow: returns diff, sets borrow_out (0 or 1).
inline std::uint64_t sbb(std::uint64_t a, std::uint64_t b,
                         std::uint64_t borrow_in, std::uint64_t& borrow_out) {
    const __uint128_t d = static_cast<__uint128_t>(a) -
                          static_cast<__uint128_t>(b) -
                          static_cast<__uint128_t>(borrow_in);
    // borrow occurred iff result high bit propagated.
    borrow_out = static_cast<std::uint64_t>(d >> 64) & 1ULL;
    return static_cast<std::uint64_t>(d);
}

// Conditional subtract of q (constant-time): if (a >= q) a -= q.
// "ge_mask" is 0 when a < q, all-ones when a >= q. We compute
// a - q and re-add q masked by the borrow to undo when a < q.
inline void cond_sub_q(std::uint64_t a[4]) {
    std::uint64_t b = 0;
    std::uint64_t r0 = sbb(a[0], Q0, 0, b);
    std::uint64_t r1 = sbb(a[1], Q1, b, b);
    std::uint64_t r2 = sbb(a[2], Q2, b, b);
    std::uint64_t r3 = sbb(a[3], Q3, b, b);
    // If borrow=1 then a < q, keep a; else a >= q, take r.
    const std::uint64_t mask = b - 1ULL;  // borrow=1 -> mask=0; borrow=0 -> mask=all-ones
    a[0] = (a[0] & ~mask) | (r0 & mask);
    a[1] = (a[1] & ~mask) | (r1 & mask);
    a[2] = (a[2] & ~mask) | (r2 & mask);
    a[3] = (a[3] & ~mask) | (r3 & mask);
}

// Conditional add of q (constant-time): if (mask==all-ones) a += q.
inline void cond_add_q(std::uint64_t a[4], std::uint64_t mask) {
    std::uint64_t c = 0;
    const std::uint64_t add0 = Q0 & mask;
    const std::uint64_t add1 = Q1 & mask;
    const std::uint64_t add2 = Q2 & mask;
    const std::uint64_t add3 = Q3 & mask;
    a[0] = adc(a[0], add0, 0, c);
    a[1] = adc(a[1], add1, c, c);
    a[2] = adc(a[2], add2, c, c);
    a[3] = adc(a[3], add3, c, c);
}

// madd0(a,b,c) -> high of a*b + c.
inline std::uint64_t madd0(std::uint64_t a, std::uint64_t b, std::uint64_t c) {
    const __uint128_t p = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b) +
                          static_cast<__uint128_t>(c);
    return static_cast<std::uint64_t>(p >> 64);
}

// madd1(a,b,c) -> (hi, lo) of a*b + c.
inline void madd1(std::uint64_t a, std::uint64_t b, std::uint64_t c,
                  std::uint64_t& hi, std::uint64_t& lo) {
    const __uint128_t p = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b) +
                          static_cast<__uint128_t>(c);
    lo = static_cast<std::uint64_t>(p);
    hi = static_cast<std::uint64_t>(p >> 64);
}

// madd2(a,b,c,d) -> (hi, lo) of a*b + c + d.
inline void madd2(std::uint64_t a, std::uint64_t b, std::uint64_t c, std::uint64_t d,
                  std::uint64_t& hi, std::uint64_t& lo) {
    const __uint128_t p = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b) +
                          static_cast<__uint128_t>(c) +
                          static_cast<__uint128_t>(d);
    lo = static_cast<std::uint64_t>(p);
    hi = static_cast<std::uint64_t>(p >> 64);
}

// CIOS Montgomery multiplication (Algorithm 2 of El Housni / Botrel,
// equivalent to the gnark-crypto _mulGeneric path).
// Computes z = x * y * R^{-1} mod q, where x, y < q.
inline void cios_mul(const std::uint64_t x[4], const std::uint64_t y[4],
                     std::uint64_t z[4]) {
    std::uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;
    std::uint64_t C, D, m;
    std::uint64_t hi, lo;

    for (int i = 0; i < 4; ++i) {
        const std::uint64_t yi = y[i];

        // First loop: t += yi * x  (t is 5 limbs).
        if (i == 0) {
            mul_u64(yi, x[0], C, t0);
            madd1(yi, x[1], C, C, t1);
            madd1(yi, x[2], C, C, t2);
            madd1(yi, x[3], C, C, t3);
        } else {
            madd1(yi, x[0], t0, C, t0);
            madd2(yi, x[1], t1, C, C, t1);
            madd2(yi, x[2], t2, C, C, t2);
            madd2(yi, x[3], t3, C, C, t3);
        }
        // t4 += C  (with overflow into D)
        std::uint64_t cc = 0;
        t4 = adc(t4, C, 0, cc);
        D = cc;

        // m = t0 * qInvNeg  (mod 2^64)
        m = t0 * QINV_NEG;

        // Second loop: t = (t + m*q) >> 64
        C = madd0(m, Q0, t0);
        madd2(m, Q1, t1, C, C, t0);
        madd2(m, Q2, t2, C, C, t1);
        madd2(m, Q3, t3, C, C, t2);

        // t3 = t4 + C, t4 = 0 + D + carry
        cc = 0;
        t3 = adc(t4, C, 0, cc);
        t4 = adc(0, D, cc, cc);
    }

    // If t4 != 0 we definitely overflow once: t -= q.
    if (t4 != 0) {
        std::uint64_t b = 0;
        z[0] = sbb(t0, Q0, 0, b);
        z[1] = sbb(t1, Q1, b, b);
        z[2] = sbb(t2, Q2, b, b);
        z[3] = sbb(t3, Q3, b, b);
        return;
    }

    z[0] = t0;
    z[1] = t1;
    z[2] = t2;
    z[3] = t3;
    cond_sub_q(z);
}

inline bool less_than_q(const std::uint64_t a[4]) {
    if (a[3] != Q3) return a[3] < Q3;
    if (a[2] != Q2) return a[2] < Q2;
    if (a[1] != Q1) return a[1] < Q1;
    return a[0] < Q0;
}

}  // namespace

// ----- Constants -----------------------------------------------------------

Fp Fp::zero() { return Fp(); }

Fp Fp::one() { return Fp({R0, R1, R2, R3}); }

// ----- Predicates ----------------------------------------------------------

bool Fp::is_zero() const {
    return (limbs[0] | limbs[1] | limbs[2] | limbs[3]) == 0;
}

bool Fp::is_one() const {
    return limbs[0] == R0 && limbs[1] == R1 && limbs[2] == R2 && limbs[3] == R3;
}

bool Fp::equal(const Fp& other) const {
    return limbs[0] == other.limbs[0] && limbs[1] == other.limbs[1] &&
           limbs[2] == other.limbs[2] && limbs[3] == other.limbs[3];
}

// ----- Arithmetic ----------------------------------------------------------

Fp Fp::add(const Fp& a, const Fp& b) {
    Fp r;
    std::uint64_t c = 0;
    r.limbs[0] = adc(a.limbs[0], b.limbs[0], 0, c);
    r.limbs[1] = adc(a.limbs[1], b.limbs[1], c, c);
    r.limbs[2] = adc(a.limbs[2], b.limbs[2], c, c);
    r.limbs[3] = adc(a.limbs[3], b.limbs[3], c, c);
    cond_sub_q(r.limbs.data());
    return r;
}

Fp Fp::sub(const Fp& a, const Fp& b) {
    Fp r;
    std::uint64_t br = 0;
    r.limbs[0] = sbb(a.limbs[0], b.limbs[0], 0, br);
    r.limbs[1] = sbb(a.limbs[1], b.limbs[1], br, br);
    r.limbs[2] = sbb(a.limbs[2], b.limbs[2], br, br);
    r.limbs[3] = sbb(a.limbs[3], b.limbs[3], br, br);
    // If borrow, add q back (constant-time mask).
    const std::uint64_t mask = 0ULL - br;  // br=1 -> all-ones, br=0 -> 0
    cond_add_q(r.limbs.data(), mask);
    return r;
}

Fp Fp::neg(const Fp& a) {
    // q - a, but if a == 0 result must be 0 (q itself is not a canonical rep).
    // Constant-time: nz != 0 iff a != 0.
    const std::uint64_t nz = (a.limbs[0] | a.limbs[1] | a.limbs[2] | a.limbs[3]);
    // m = all-ones if a != 0; 0 if a == 0.
    const std::uint64_t m = 0ULL - ((nz | (0ULL - nz)) >> 63);

    Fp r;
    std::uint64_t b = 0;
    r.limbs[0] = sbb(Q0, a.limbs[0], 0, b);
    r.limbs[1] = sbb(Q1, a.limbs[1], b, b);
    r.limbs[2] = sbb(Q2, a.limbs[2], b, b);
    r.limbs[3] = sbb(Q3, a.limbs[3], b, b);
    r.limbs[0] &= m;
    r.limbs[1] &= m;
    r.limbs[2] &= m;
    r.limbs[3] &= m;
    return r;
}

Fp Fp::mul(const Fp& a, const Fp& b) {
    Fp r;
    cios_mul(a.limbs.data(), b.limbs.data(), r.limbs.data());
    return r;
}

Fp Fp::square(const Fp& a) {
    return mul(a, a);
}

// Fermat's little theorem: a^(q-2) = a^{-1} mod q (for a != 0).
// q - 2 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfefffffffeffffffff
// Square-and-multiply with fixed 256-bit loop. Reads of bit and the
// conditional multiply are masked (constant-time wrt the *value* of `a`;
// the exponent is a hard-coded constant, so its bits leaking is fine).
Fp Fp::inv(const Fp& a) {
    if (a.is_zero()) {
        return Fp::zero();
    }

    // q - 2 as four little-endian limbs.
    constexpr std::uint64_t E0 = Q0 - 2ULL;  // 0xffffffff00000001 - 2 = 0xfffffffeffffffff
    constexpr std::uint64_t E1 = Q1;
    constexpr std::uint64_t E2 = Q2;
    constexpr std::uint64_t E3 = Q3;
    const std::uint64_t e[4] = {E0, E1, E2, E3};

    Fp result = Fp::one();
    Fp base = a;

    for (int limb = 0; limb < 4; ++limb) {
        std::uint64_t bits = e[limb];
        for (int i = 0; i < 64; ++i) {
            const std::uint64_t bit = bits & 1ULL;
            // Constant-time conditional multiply.
            Fp prod = mul(result, base);
            const std::uint64_t mask = 0ULL - bit;  // -1 if bit=1, 0 if bit=0
            for (int k = 0; k < 4; ++k) {
                result.limbs[k] = (result.limbs[k] & ~mask) | (prod.limbs[k] & mask);
            }
            base = square(base);
            bits >>= 1;
        }
    }
    return result;
}

// ----- Codec ---------------------------------------------------------------

bool Fp::from_bytes_le(const std::uint8_t bytes[32], Fp& out) {
    std::uint64_t z[4];
    for (int i = 0; i < 4; ++i) {
        z[i] = static_cast<std::uint64_t>(bytes[8 * i + 0]) |
               (static_cast<std::uint64_t>(bytes[8 * i + 1]) << 8) |
               (static_cast<std::uint64_t>(bytes[8 * i + 2]) << 16) |
               (static_cast<std::uint64_t>(bytes[8 * i + 3]) << 24) |
               (static_cast<std::uint64_t>(bytes[8 * i + 4]) << 32) |
               (static_cast<std::uint64_t>(bytes[8 * i + 5]) << 40) |
               (static_cast<std::uint64_t>(bytes[8 * i + 6]) << 48) |
               (static_cast<std::uint64_t>(bytes[8 * i + 7]) << 56);
    }
    if (!less_than_q(z)) {
        return false;
    }
    // Convert canonical -> Montgomery: z * R^2 / R = z * R.
    Fp tmp;
    tmp.limbs[0] = z[0];
    tmp.limbs[1] = z[1];
    tmp.limbs[2] = z[2];
    tmp.limbs[3] = z[3];
    Fp r2 = Fp({R2_0, R2_1, R2_2, R2_3});
    out = mul(tmp, r2);
    return true;
}

void Fp::to_bytes_le(std::uint8_t bytes[32]) const {
    // From Montgomery -> canonical: multiply by 1 (limbs {1, 0, 0, 0}).
    Fp one_canonical = Fp({1ULL, 0ULL, 0ULL, 0ULL});
    Fp z = mul(*this, one_canonical);
    for (int i = 0; i < 4; ++i) {
        const std::uint64_t v = z.limbs[i];
        bytes[8 * i + 0] = static_cast<std::uint8_t>(v);
        bytes[8 * i + 1] = static_cast<std::uint8_t>(v >> 8);
        bytes[8 * i + 2] = static_cast<std::uint8_t>(v >> 16);
        bytes[8 * i + 3] = static_cast<std::uint8_t>(v >> 24);
        bytes[8 * i + 4] = static_cast<std::uint8_t>(v >> 32);
        bytes[8 * i + 5] = static_cast<std::uint8_t>(v >> 40);
        bytes[8 * i + 6] = static_cast<std::uint8_t>(v >> 48);
        bytes[8 * i + 7] = static_cast<std::uint8_t>(v >> 56);
    }
}

bool Fp::from_bytes_be(const std::uint8_t bytes[32], Fp& out) {
    std::uint8_t le[32];
    for (int i = 0; i < 32; ++i) le[i] = bytes[31 - i];
    return from_bytes_le(le, out);
}

void Fp::to_bytes_be(std::uint8_t bytes[32]) const {
    std::uint8_t le[32];
    to_bytes_le(le);
    for (int i = 0; i < 32; ++i) bytes[i] = le[31 - i];
}

namespace {

// (q-1)/2 in canonical (LE) limbs:
//   q-1   = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000
//   /2    = 0x39f6d3a994cebea4199cec0404d0ec02a9ded2017fff2dff7fffffff80000000
// LE limbs (limb0 = least significant):
constexpr std::uint64_t QM1H_0 = 0x7fffffff80000000ULL;
constexpr std::uint64_t QM1H_1 = 0xa9ded2017fff2dffULL;
constexpr std::uint64_t QM1H_2 = 0x199cec0404d0ec02ULL;
constexpr std::uint64_t QM1H_3 = 0x39f6d3a994cebea4ULL;

// Generic exponentiation by an LE 4-limb constant. Used for Legendre and
// Tonelli-Shanks. Public-exponent square-and-multiply (constants are not
// secret here; only the *base* `a` is "secret" in some contexts).
inline Fp pow_limbs(const Fp& base, const std::uint64_t exp[4]) {
    Fp result = Fp::one();
    Fp b = base;
    for (int limb = 0; limb < 4; ++limb) {
        std::uint64_t bits = exp[limb];
        for (int i = 0; i < 64; ++i) {
            if (bits & 1ULL) {
                result = Fp::mul(result, b);
            }
            b = Fp::square(b);
            bits >>= 1;
        }
    }
    return result;
}

}  // namespace

bool Fp::lex_largest() const {
    // Need canonical form first (multiply by 1 to convert from Montgomery).
    Fp one_canonical = Fp({1ULL, 0ULL, 0ULL, 0ULL});
    Fp z = mul(*this, one_canonical);
    // Compare z (canonical) against (q-1)/2: largest iff z > (q-1)/2.
    if (z.limbs[3] != QM1H_3) return z.limbs[3] > QM1H_3;
    if (z.limbs[2] != QM1H_2) return z.limbs[2] > QM1H_2;
    if (z.limbs[1] != QM1H_1) return z.limbs[1] > QM1H_1;
    return z.limbs[0] > QM1H_0;
}

int Fp::legendre(const Fp& a) {
    if (a.is_zero()) return 0;
    // a^((q-1)/2): 1 if QR, -1 (== q-1) if non-QR.
    const std::uint64_t e[4] = {QM1H_0, QM1H_1, QM1H_2, QM1H_3};
    Fp r = pow_limbs(a, e);
    if (r.is_one()) return 1;
    return -1;
}

bool Fp::sqrt(const Fp& a, Fp& out) {
    if (a.is_zero()) {
        out = Fp::zero();
        return true;
    }
    if (Fp::legendre(a) != 1) return false;

    // q - 1 = q1 * 2^s where s = 32, q1 = (q-1) >> 32.
    //   q-1 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000
    //   q1  = 0x0000000073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff
    // 4 LE limbs of q1:
    constexpr std::uint64_t Q1_0 = 0xfffe5bfeffffffffULL;
    constexpr std::uint64_t Q1_1 = 0x09a1d80553bda402ULL;
    constexpr std::uint64_t Q1_2 = 0x299d7d483339d808ULL;
    constexpr std::uint64_t Q1_3 = 0x0000000073eda753ULL;
    constexpr int S = 32;

    // (q1 + 1) / 2 in 4 LE limbs:
    //   q1+1 = 0x0000000073eda753299d7d483339d80809a1d80553bda402fffe5bff00000000
    //   /2   = 0x0000000039f6d3a994cebea4199cec0404d0ec02a9ded2017fff2dff80000000
    constexpr std::uint64_t E0 = 0x7fff2dff80000000ULL;
    constexpr std::uint64_t E1 = 0x04d0ec02a9ded201ULL;
    constexpr std::uint64_t E2 = 0x94cebea4199cec04ULL;
    constexpr std::uint64_t E3 = 0x0000000039f6d3a9ULL;

    // g = quadratic non-residue. For q = bls12-381 fr, g = 7 works (used by
    // gnark; also a primitive root mod q, sufficient for TS as long as it
    // is a non-residue, which 7 is for this q).
    Fp g;
    {
        std::uint8_t b7[32] = {7,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                               0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
        Fp::from_bytes_le(b7, g);
    }

    const std::uint64_t q1[4] = {Q1_0, Q1_1, Q1_2, Q1_3};
    const std::uint64_t e_init[4] = {E0, E1, E2, E3};

    Fp c = pow_limbs(g, q1);
    Fp x = pow_limbs(a, e_init);
    Fp t = pow_limbs(a, q1);
    int M = S;

    // TS main loop. Variable iteration count; depends on a, but only used
    // outside hot crypto paths (deserialize / hash-to-curve), so this is
    // acceptable.
    while (!t.is_one()) {
        // find least m in [0, M) such that t^(2^m) == 1
        Fp t_pow = t;
        int m = 0;
        while (!t_pow.is_one() && m < M) {
            t_pow = Fp::square(t_pow);
            ++m;
        }
        if (m == M) return false;  // not actually a residue
        // b = c^(2^(M - m - 1))
        Fp b = c;
        for (int i = 0; i < M - m - 1; ++i) b = Fp::square(b);
        x = Fp::mul(x, b);
        c = Fp::square(b);
        t = Fp::mul(t, c);
        M = m;
    }

    // Verify x*x == a (defense in depth against any constant errors above).
    if (!Fp::square(x).equal(a)) return false;

    // Return non-largest root.
    if (x.lex_largest()) x = Fp::neg(x);
    out = x;
    return true;
}

}  // namespace kinet::banderwagon

// =============================================================================
// extern "C" thin wrappers so `nm` reports T _Fp_*  symbols (Mach-O / ELF).
// These are direct passthroughs; no extra logic.
// =============================================================================

extern "C" {

using kinet::banderwagon::Fp;

void Fp_zero(Fp* out) { *out = Fp::zero(); }
void Fp_one(Fp* out) { *out = Fp::one(); }
int  Fp_is_zero(const Fp* a) { return a->is_zero() ? 1 : 0; }
int  Fp_is_one(const Fp* a) { return a->is_one() ? 1 : 0; }
int  Fp_equal(const Fp* a, const Fp* b) { return a->equal(*b) ? 1 : 0; }
void Fp_add(Fp* out, const Fp* a, const Fp* b) { *out = Fp::add(*a, *b); }
void Fp_sub(Fp* out, const Fp* a, const Fp* b) { *out = Fp::sub(*a, *b); }
void Fp_neg(Fp* out, const Fp* a) { *out = Fp::neg(*a); }
void Fp_mul(Fp* out, const Fp* a, const Fp* b) { *out = Fp::mul(*a, *b); }
void Fp_square(Fp* out, const Fp* a) { *out = Fp::square(*a); }
void Fp_inv(Fp* out, const Fp* a) { *out = Fp::inv(*a); }
int  Fp_from_bytes_le(Fp* out, const std::uint8_t bytes[32]) {
    return Fp::from_bytes_le(bytes, *out) ? 1 : 0;
}
void Fp_to_bytes_le(const Fp* a, std::uint8_t bytes[32]) {
    a->to_bytes_le(bytes);
}
int  Fp_from_bytes_be(Fp* out, const std::uint8_t bytes[32]) {
    return Fp::from_bytes_be(bytes, *out) ? 1 : 0;
}
void Fp_to_bytes_be(const Fp* a, std::uint8_t bytes[32]) {
    a->to_bytes_be(bytes);
}
int  Fp_legendre(const Fp* a) { return Fp::legendre(*a); }
int  Fp_lex_largest(const Fp* a) { return a->lex_largest() ? 1 : 0; }
int  Fp_sqrt(Fp* out, const Fp* a) { return Fp::sqrt(*a, *out) ? 1 : 0; }

}  // extern "C"

// =============================================================================
// internal:: accessors for the Metal codegen. Single source of truth for the
// modulus / Montgomery constants -- the GPU constant table is generated from
// these, so any drift fails compilation.
// =============================================================================
namespace kinet::banderwagon::internal {

void fp_modulus(std::uint64_t out[4]) {
    out[0] = Q0; out[1] = Q1; out[2] = Q2; out[3] = Q3;
}
void fp_r_squared(std::uint64_t out[4]) {
    out[0] = R2_0; out[1] = R2_1; out[2] = R2_2; out[3] = R2_3;
}
void fp_r_mod_q(std::uint64_t out[4]) {
    out[0] = R0; out[1] = R1; out[2] = R2; out[3] = R3;
}
std::uint64_t fp_qinv_neg() { return QINV_NEG; }

}  // namespace kinet::banderwagon::internal

// SPDX-License-Identifier: Apache-2.0
//
// banderwagon/fr.cpp -- Bandersnatch scalar field arithmetic.
// First-party. No vendoring. See fr.hpp for the contract.

#include "fr.hpp"

#include <cstring>

namespace kinet::banderwagon {

// Modulus r = 0x1cfb69d4ca675f520cce760202687600ff8f87007419047174fd06b52876e7e1
//           = 13108968793781547619861935127046491459309155893440570251786403306729687672801
constexpr std::uint64_t R0 = 0x74fd06b52876e7e1ULL;
constexpr std::uint64_t R1 = 0xff8f870074190471ULL;
constexpr std::uint64_t R2 = 0x0cce760202687600ULL;
constexpr std::uint64_t R3 = 0x1cfb69d4ca675f52ULL;

// q' such that r * q' = -1 mod 2^64  (i.e. -r^{-1} mod 2^64).
constexpr std::uint64_t QINV_NEG = 0xf19f22295cc063dfULL;

// R^2 mod r  (R = 2^256). Used to convert into Montgomery form.
constexpr std::uint64_t RSQ_0 = 0xdbb4f5d658db47cbULL;
constexpr std::uint64_t RSQ_1 = 0x40fa7ca27fecb938ULL;
constexpr std::uint64_t RSQ_2 = 0xaa9e6daec0055ceaULL;
constexpr std::uint64_t RSQ_3 = 0x0ae793ddb14aec7dULL;

// R mod r (this *is* the Montgomery representation of 1).
constexpr std::uint64_t RMONT_0 = 0x5817ca56bc48c0f8ULL;
constexpr std::uint64_t RMONT_1 = 0x0383c7fc5f37dc74ULL;
constexpr std::uint64_t RMONT_2 = 0x998c4fefecbc4ff8ULL;
constexpr std::uint64_t RMONT_3 = 0x1824b159acc5056fULL;

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

// Conditional subtract of r (constant-time): if (a >= r) a -= r.
inline void cond_sub_r(std::uint64_t a[4]) {
    std::uint64_t b = 0;
    std::uint64_t r0 = sbb(a[0], R0, 0, b);
    std::uint64_t r1 = sbb(a[1], R1, b, b);
    std::uint64_t r2 = sbb(a[2], R2, b, b);
    std::uint64_t r3 = sbb(a[3], R3, b, b);
    // If borrow=1 then a < r, keep a; else a >= r, take r.
    const std::uint64_t mask = b - 1ULL;  // borrow=1 -> mask=0; borrow=0 -> mask=all-ones
    a[0] = (a[0] & ~mask) | (r0 & mask);
    a[1] = (a[1] & ~mask) | (r1 & mask);
    a[2] = (a[2] & ~mask) | (r2 & mask);
    a[3] = (a[3] & ~mask) | (r3 & mask);
}

// Conditional add of r (constant-time): if (mask==all-ones) a += r.
inline void cond_add_r(std::uint64_t a[4], std::uint64_t mask) {
    std::uint64_t c = 0;
    const std::uint64_t add0 = R0 & mask;
    const std::uint64_t add1 = R1 & mask;
    const std::uint64_t add2 = R2 & mask;
    const std::uint64_t add3 = R3 & mask;
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
// Computes z = x * y * R^{-1} mod r, where x, y < r.
inline void cios_mul(const std::uint64_t x[4], const std::uint64_t y[4],
                     std::uint64_t z[4]) {
    std::uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;
    std::uint64_t C, D, m;

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

        // Second loop: t = (t + m*r) >> 64
        C = madd0(m, R0, t0);
        madd2(m, R1, t1, C, C, t0);
        madd2(m, R2, t2, C, C, t1);
        madd2(m, R3, t3, C, C, t2);

        // t3 = t4 + C, t4 = 0 + D + carry
        cc = 0;
        t3 = adc(t4, C, 0, cc);
        t4 = adc(0, D, cc, cc);
    }

    // If t4 != 0 we definitely overflow once: t -= r.
    if (t4 != 0) {
        std::uint64_t b = 0;
        z[0] = sbb(t0, R0, 0, b);
        z[1] = sbb(t1, R1, b, b);
        z[2] = sbb(t2, R2, b, b);
        z[3] = sbb(t3, R3, b, b);
        return;
    }

    z[0] = t0;
    z[1] = t1;
    z[2] = t2;
    z[3] = t3;
    cond_sub_r(z);
}

inline bool less_than_r(const std::uint64_t a[4]) {
    if (a[3] != R3) return a[3] < R3;
    if (a[2] != R2) return a[2] < R2;
    if (a[1] != R1) return a[1] < R1;
    return a[0] < R0;
}

}  // namespace

// ----- Constants -----------------------------------------------------------

Fr Fr::zero() { return Fr(); }

Fr Fr::one() { return Fr({RMONT_0, RMONT_1, RMONT_2, RMONT_3}); }

// ----- Predicates ----------------------------------------------------------

bool Fr::is_zero() const {
    return (limbs[0] | limbs[1] | limbs[2] | limbs[3]) == 0;
}

bool Fr::is_one() const {
    return limbs[0] == RMONT_0 && limbs[1] == RMONT_1 &&
           limbs[2] == RMONT_2 && limbs[3] == RMONT_3;
}

bool Fr::equal(const Fr& other) const {
    return limbs[0] == other.limbs[0] && limbs[1] == other.limbs[1] &&
           limbs[2] == other.limbs[2] && limbs[3] == other.limbs[3];
}

// ----- Arithmetic ----------------------------------------------------------

Fr Fr::add(const Fr& a, const Fr& b) {
    Fr r;
    std::uint64_t c = 0;
    r.limbs[0] = adc(a.limbs[0], b.limbs[0], 0, c);
    r.limbs[1] = adc(a.limbs[1], b.limbs[1], c, c);
    r.limbs[2] = adc(a.limbs[2], b.limbs[2], c, c);
    r.limbs[3] = adc(a.limbs[3], b.limbs[3], c, c);
    cond_sub_r(r.limbs.data());
    return r;
}

Fr Fr::sub(const Fr& a, const Fr& b) {
    Fr r;
    std::uint64_t br = 0;
    r.limbs[0] = sbb(a.limbs[0], b.limbs[0], 0, br);
    r.limbs[1] = sbb(a.limbs[1], b.limbs[1], br, br);
    r.limbs[2] = sbb(a.limbs[2], b.limbs[2], br, br);
    r.limbs[3] = sbb(a.limbs[3], b.limbs[3], br, br);
    // If borrow, add r back (constant-time mask).
    const std::uint64_t mask = 0ULL - br;  // br=1 -> all-ones, br=0 -> 0
    cond_add_r(r.limbs.data(), mask);
    return r;
}

Fr Fr::neg(const Fr& a) {
    // r - a, but if a == 0 result must be 0 (r itself is not a canonical rep).
    // Constant-time: nz != 0 iff a != 0.
    const std::uint64_t nz = (a.limbs[0] | a.limbs[1] | a.limbs[2] | a.limbs[3]);
    // m = all-ones if a != 0; 0 if a == 0.
    const std::uint64_t m = 0ULL - ((nz | (0ULL - nz)) >> 63);

    Fr r;
    std::uint64_t b = 0;
    r.limbs[0] = sbb(R0, a.limbs[0], 0, b);
    r.limbs[1] = sbb(R1, a.limbs[1], b, b);
    r.limbs[2] = sbb(R2, a.limbs[2], b, b);
    r.limbs[3] = sbb(R3, a.limbs[3], b, b);
    r.limbs[0] &= m;
    r.limbs[1] &= m;
    r.limbs[2] &= m;
    r.limbs[3] &= m;
    return r;
}

Fr Fr::mul(const Fr& a, const Fr& b) {
    Fr r;
    cios_mul(a.limbs.data(), b.limbs.data(), r.limbs.data());
    return r;
}

Fr Fr::square(const Fr& a) {
    return mul(a, a);
}

// Fermat's little theorem: a^(r-2) = a^{-1} mod r (for a != 0).
// r - 2 = 0x1cfb69d4ca675f520cce760202687600ff8f87007419047174fd06b52876e7df
// Square-and-multiply with fixed 256-bit loop. Reads of bit and the
// conditional multiply are masked (constant-time wrt the *value* of `a`;
// the exponent is a hard-coded constant, so its bits leaking is fine).
Fr Fr::inv(const Fr& a) {
    if (a.is_zero()) {
        return Fr::zero();
    }

    // r - 2 as four little-endian limbs.
    constexpr std::uint64_t E0 = R0 - 2ULL;  // 0x74fd06b52876e7e1 - 2 = 0x74fd06b52876e7df
    constexpr std::uint64_t E1 = R1;
    constexpr std::uint64_t E2 = R2;
    constexpr std::uint64_t E3 = R3;
    const std::uint64_t e[4] = {E0, E1, E2, E3};

    Fr result = Fr::one();
    Fr base = a;

    for (int limb = 0; limb < 4; ++limb) {
        std::uint64_t bits = e[limb];
        for (int i = 0; i < 64; ++i) {
            const std::uint64_t bit = bits & 1ULL;
            // Constant-time conditional multiply.
            Fr prod = mul(result, base);
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

bool Fr::from_bytes_le(const std::uint8_t bytes[32], Fr& out) {
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
    if (!less_than_r(z)) {
        return false;
    }
    // Convert canonical -> Montgomery: z * R^2 / R = z * R.
    Fr tmp;
    tmp.limbs[0] = z[0];
    tmp.limbs[1] = z[1];
    tmp.limbs[2] = z[2];
    tmp.limbs[3] = z[3];
    Fr r2 = Fr({RSQ_0, RSQ_1, RSQ_2, RSQ_3});
    out = mul(tmp, r2);
    return true;
}

void Fr::to_bytes_le(std::uint8_t bytes[32]) const {
    // From Montgomery -> canonical: multiply by 1 (limbs {1, 0, 0, 0}).
    Fr one_canonical = Fr({1ULL, 0ULL, 0ULL, 0ULL});
    Fr z = mul(*this, one_canonical);
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

}  // namespace kinet::banderwagon

// =============================================================================
// extern "C" thin wrappers so `nm` reports T _Fr_*  symbols (Mach-O / ELF).
// These are direct passthroughs; no extra logic.
// =============================================================================

extern "C" {

using kinet::banderwagon::Fr;

void Fr_zero(Fr* out) { *out = Fr::zero(); }
void Fr_one(Fr* out) { *out = Fr::one(); }
int  Fr_is_zero(const Fr* a) { return a->is_zero() ? 1 : 0; }
int  Fr_is_one(const Fr* a) { return a->is_one() ? 1 : 0; }
int  Fr_equal(const Fr* a, const Fr* b) { return a->equal(*b) ? 1 : 0; }
void Fr_add(Fr* out, const Fr* a, const Fr* b) { *out = Fr::add(*a, *b); }
void Fr_sub(Fr* out, const Fr* a, const Fr* b) { *out = Fr::sub(*a, *b); }
void Fr_neg(Fr* out, const Fr* a) { *out = Fr::neg(*a); }
void Fr_mul(Fr* out, const Fr* a, const Fr* b) { *out = Fr::mul(*a, *b); }
void Fr_square(Fr* out, const Fr* a) { *out = Fr::square(*a); }
void Fr_inv(Fr* out, const Fr* a) { *out = Fr::inv(*a); }
int  Fr_from_bytes_le(Fr* out, const std::uint8_t bytes[32]) {
    return Fr::from_bytes_le(bytes, *out) ? 1 : 0;
}
void Fr_to_bytes_le(const Fr* a, std::uint8_t bytes[32]) {
    a->to_bytes_le(bytes);
}

}  // extern "C"

// =============================================================================
// internal:: accessors for the Metal codegen (single source of truth for
// the modulus / Montgomery constants).
// =============================================================================
namespace kinet::banderwagon::internal {

void fr_modulus(std::uint64_t out[4]) {
    out[0] = kinet::banderwagon::R0;
    out[1] = kinet::banderwagon::R1;
    out[2] = kinet::banderwagon::R2;
    out[3] = kinet::banderwagon::R3;
}
void fr_r_squared(std::uint64_t out[4]) {
    out[0] = kinet::banderwagon::RSQ_0;
    out[1] = kinet::banderwagon::RSQ_1;
    out[2] = kinet::banderwagon::RSQ_2;
    out[3] = kinet::banderwagon::RSQ_3;
}
void fr_r_mod_r(std::uint64_t out[4]) {
    out[0] = kinet::banderwagon::RMONT_0;
    out[1] = kinet::banderwagon::RMONT_1;
    out[2] = kinet::banderwagon::RMONT_2;
    out[3] = kinet::banderwagon::RMONT_3;
}
std::uint64_t fr_rinv_neg() { return kinet::banderwagon::QINV_NEG; }

}  // namespace kinet::banderwagon::internal

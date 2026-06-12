// Goldilocks field (p = 2^64 - 2^32 + 1 = 0xFFFFFFFF00000001) arithmetic.
//
// Single-u64 representation. Inputs are kept in [0, p); add/sub use
// branchful conditional subtraction; multiplication uses a 128-bit intermediate
// and Goldilocks-specific reduction (Solinas-prime form):
//   given t = lo + hi * 2^64 = lo + hi * (2^32 - 1) (mod p),
//   write hi = a + b*2^32, then t mod p = lo + b*(p - 2^32 + 1)... we use the
//   classic two-step reduction described in the Plonky2 / Polygon Zero papers.
//
// The reference upstream we cross-check against
// (github.com/HorizenLabs/poseidon2) operates over the same Goldilocks field
// via ark_ff::PrimeField; outputs match byte-for-byte (see test/poseidon_goldilocks_test.cpp).

#pragma once
#include <cstdint>

namespace kinet::crypto::poseidon::gf {

// p = 2^64 - 2^32 + 1
inline constexpr uint64_t MOD = 0xFFFFFFFF00000001ULL;
// EPSILON = 2^64 mod p = 2^32 - 1
inline constexpr uint64_t EPSILON = 0xFFFFFFFFULL;

// Reduce x in [0, 2*p) to [0, p).
inline constexpr uint64_t reduce_once(uint64_t x) noexcept {
    return (x >= MOD) ? (x - MOD) : x;
}

// Bring an arbitrary u64 into canonical form. Equivalent to `reduce_once` for
// inputs already < 2*p; for inputs in [2*p, 2^64) it loops a few times.
inline constexpr uint64_t canon(uint64_t x) noexcept {
    while (x >= MOD) x -= MOD;
    return x;
}

// Modular addition. Both inputs must be < p.
inline constexpr uint64_t add(uint64_t a, uint64_t b) noexcept {
    // a + b < 2*p < 2^65, but we have only 64 bits. Detect carry.
    uint64_t s = a + b;
    bool wrap = (s < a);                 // arithmetic carry
    if (wrap) s += EPSILON;              // 2^64 ≡ 2^32 - 1 (mod p)
    return reduce_once(s);
}

// Modular subtraction. Both inputs must be < p.
inline constexpr uint64_t sub(uint64_t a, uint64_t b) noexcept {
    uint64_t d = a - b;
    bool borrow = (a < b);
    if (borrow) d -= EPSILON;            // -2^64 ≡ -(2^32 - 1) (mod p)
    return d;
}

// Modular doubling.
inline constexpr uint64_t dbl(uint64_t a) noexcept { return add(a, a); }

// Modular negation.
inline constexpr uint64_t neg(uint64_t a) noexcept {
    return a == 0 ? 0 : (MOD - a);
}

// Reduce a 128-bit product (lo, hi) to a single u64 in [0, p).
//
//   t = lo + hi * 2^64
//   Split hi = hi_lo (low 32 bits) + hi_hi (high 32 bits) << 32.
//   Use 2^64 ≡ 2^32 - 1 (mod p) and 2^96 ≡ -1 (mod p).
//
//   t ≡ lo + hi_lo * (2^32 - 1) - hi_hi
//
// This is the canonical Goldilocks reduction (Polygon Zero / Plonky2,
// Mir Protocol's plonky2 paper §2.2).
inline uint64_t reduce128(uint64_t lo, uint64_t hi) noexcept {
    uint32_t hi_hi = (uint32_t)(hi >> 32);
    uint32_t hi_lo = (uint32_t)hi;

    // r = lo - hi_hi (mod p)
    uint64_t r;
    {
        uint64_t d = lo - (uint64_t)hi_hi;
        bool borrow = (lo < (uint64_t)hi_hi);
        if (borrow) d -= EPSILON;
        r = d;
    }

    // r += hi_lo * (2^32 - 1) (mod p)
    // Compute hi_lo * 2^32 - hi_lo, all mod p.
    uint64_t hi_lo_shifted = ((uint64_t)hi_lo) << 32;  // < 2^64
    // Reduce hi_lo_shifted: it's at most (2^32-1)*2^32 < 2^64, so already < 2^64; might be >= p.
    if (hi_lo_shifted >= MOD) hi_lo_shifted -= MOD;
    r = add(r, hi_lo_shifted);
    r = sub(r, (uint64_t)hi_lo);

    return r;
}

// Modular multiplication. Both inputs must be < p.
inline uint64_t mul(uint64_t a, uint64_t b) noexcept {
    unsigned __int128 t = (unsigned __int128)a * (unsigned __int128)b;
    return reduce128((uint64_t)t, (uint64_t)(t >> 64));
}

// Squaring.
inline uint64_t sqr(uint64_t a) noexcept { return mul(a, a); }

// Exponentiation by 7 (the Poseidon2-Goldilocks-t=8 sBox: x^7).
//   y = x^2; z = y^2 = x^4; r = x * y * z = x * x^2 * x^4 = x^7.
inline uint64_t pow7(uint64_t x) noexcept {
    uint64_t x2 = sqr(x);
    uint64_t x4 = sqr(x2);
    return mul(mul(x, x2), x4);
}

// Generic exponentiation (left-to-right square-and-multiply). Used only by
// tests; the hot path uses pow7().
inline uint64_t pow(uint64_t base, uint64_t exp) noexcept {
    uint64_t r = 1;
    while (exp != 0) {
        if (exp & 1ULL) r = mul(r, base);
        base = sqr(base);
        exp >>= 1;
    }
    return r;
}

}  // namespace kinet::crypto::poseidon::gf

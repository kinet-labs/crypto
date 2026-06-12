// First-party Montgomery field arithmetic for BLS12-381 base field Fp.
//
//   p = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F624
//        1EABFFFEB153FFFFB9FEFFFFFFFFAAAB         (381 bits)
//
// Algorithms used:
//   * CIOS Montgomery multiplication (Koc/Acar/Kaliski 1996; HAC §14.36).
//   * Schoolbook 384x384 -> 768 product, then a 6-iteration CIOS reduction.
//
// Layout: 6 x uint64_t little-endian limbs.  This is byte-equal to blst's
// vec384 / blst_fp -- the same Montgomery domain, the same limb order.  It
// matches the BLS_P / BLS_R / BLS_R2 / BLS_P_INV constants already present in
// crypto/bls/gpu/cuda/bls_fp_ops.cuh and crypto/bls/gpu/wgsl/bls_fp_ops.wgsl
// so anyone holding GPU-side bytes can compare verbatim.
//
// Self-contained header. No blst, no external bigint library.  Mirrors the
// shape of crypto/bn254/cpp/bn254_fp.hpp -- only the modulus width changes.

#pragma once

#include <array>
#include <cstdint>
#include <cstring>

namespace kinet::crypto::bls12_381 {

using u64  = uint64_t;
using u128 = unsigned __int128;

// 384-bit unsigned bigint, 6 little-endian 64-bit limbs.
struct U384 {
    u64 limbs[6];

    constexpr U384() : limbs{0, 0, 0, 0, 0, 0} {}
    constexpr U384(u64 l0, u64 l1, u64 l2, u64 l3, u64 l4, u64 l5)
        : limbs{l0, l1, l2, l3, l4, l5} {}

    bool is_zero() const noexcept {
        return (limbs[0] | limbs[1] | limbs[2] |
                limbs[3] | limbs[4] | limbs[5]) == 0;
    }

    static int cmp(const U384& a, const U384& b) noexcept {
        for (int i = 5; i >= 0; --i) {
            if (a.limbs[i] < b.limbs[i]) return -1;
            if (a.limbs[i] > b.limbs[i]) return 1;
        }
        return 0;
    }

    bool operator==(const U384& o) const noexcept { return cmp(*this, o) == 0; }
    bool operator!=(const U384& o) const noexcept { return cmp(*this, o) != 0; }

    // Decode a 48-byte big-endian field element into 6 LE limbs.
    static U384 from_be48(const uint8_t b[48]) noexcept {
        U384 r;
        for (int limb = 0; limb < 6; ++limb) {
            u64 v = 0;
            const int base = (5 - limb) * 8;
            for (int i = 0; i < 8; ++i) v = (v << 8) | (u64)b[base + i];
            r.limbs[limb] = v;
        }
        return r;
    }

    void to_be48(uint8_t b[48]) const noexcept {
        for (int limb = 0; limb < 6; ++limb) {
            const int base = (5 - limb) * 8;
            u64 v = limbs[limb];
            for (int i = 7; i >= 0; --i) {
                b[base + i] = (uint8_t)(v & 0xFF);
                v >>= 8;
            }
        }
    }

    bool bit(unsigned i) const noexcept {
        return ((limbs[i >> 6] >> (i & 63)) & 1ULL) != 0;
    }
};

// p = BLS12-381 base-field modulus.  Limbs are byte-equal to blst's BLS_P.
constexpr U384 P{
    0xB9FEFFFFFFFFAAABULL, 0x1EABFFFEB153FFFFULL, 0x6730D2A0F6B0F624ULL,
    0x64774B84F38512BFULL, 0x4B1BA7B6434BACD7ULL, 0x1A0111EA397FE69AULL};

// R   = 2^384 mod p           (a.k.a. one in Montgomery form).
constexpr U384 R_FP{
    0x760900000002FFFDULL, 0xEBF4000BC40C0002ULL, 0x5F48985753C758BAULL,
    0x77CE585370525745ULL, 0x5C071A97A256EC6DULL, 0x15F65EC3FA80E493ULL};

// R^2 = 2^768 mod p           (used to enter Montgomery form).
constexpr U384 R2_FP{
    0xF4DF1F341C341746ULL, 0x0A76E6A609D104F1ULL, 0x8DE5476C4C95B6D5ULL,
    0x67EB88A9939D83C0ULL, 0x9A793E85B519952DULL, 0x11988FE592CAE3AAULL};

// -p^{-1} mod 2^64            (CIOS reduction constant).
constexpr u64 P_INV = 0x89F3FFFCFFFCFFFDULL;

// p - 2 -- exponent for Fermat inversion.
constexpr U384 P_M2{
    0xB9FEFFFFFFFFAAA9ULL, 0x1EABFFFEB153FFFFULL, 0x6730D2A0F6B0F624ULL,
    0x64774B84F38512BFULL, 0x4B1BA7B6434BACD7ULL, 0x1A0111EA397FE69AULL};

inline U384 add_384(const U384& a, const U384& b, u64& carry) noexcept {
    U384 r;
    u64 c = 0;
    for (int i = 0; i < 6; ++i) {
        u128 t = (u128)a.limbs[i] + (u128)b.limbs[i] + c;
        r.limbs[i] = (u64)t;
        c = (u64)(t >> 64);
    }
    carry = c;
    return r;
}

inline U384 sub_384(const U384& a, const U384& b, u64& borrow) noexcept {
    U384 r;
    u64 bw = 0;
    for (int i = 0; i < 6; ++i) {
        u128 t = (u128)a.limbs[i] - (u128)b.limbs[i] - bw;
        r.limbs[i] = (u64)t;
        bw = (u64)((t >> 64) & 1ULL);
    }
    borrow = bw;
    return r;
}

inline U384 mod_add(const U384& a, const U384& b, const U384& m) noexcept {
    u64 c;
    U384 t = add_384(a, b, c);
    if (c != 0 || U384::cmp(t, m) >= 0) {
        u64 bw;
        t = sub_384(t, m, bw);
    }
    return t;
}

inline U384 mod_sub(const U384& a, const U384& b, const U384& m) noexcept {
    u64 bw;
    U384 t = sub_384(a, b, bw);
    if (bw != 0) {
        u64 c;
        t = add_384(t, m, c);
    }
    return t;
}

// CIOS Montgomery multiplication: returns a * b * R^{-1} mod m.
//   T is a 12-limb intermediate; we accumulate one column of a*b at a time
//   and reduce modulo m before moving on.  The final 13th word is folded in
//   the conditional final subtract.
inline U384 mont_mul(const U384& a, const U384& b,
                     const U384& m, u64 m_inv) noexcept {
    u64 t[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    for (int i = 0; i < 6; ++i) {
        u64 carry = 0;
        for (int j = 0; j < 6; ++j) {
            u128 prod = (u128)a.limbs[j] * (u128)b.limbs[i] + t[j] + carry;
            t[j] = (u64)prod;
            carry = (u64)(prod >> 64);
        }
        u128 sum = (u128)t[6] + carry;
        t[6] = (u64)sum;
        t[7] += (u64)(sum >> 64);

        u64 u = t[0] * m_inv;
        carry = 0;
        for (int j = 0; j < 6; ++j) {
            u128 prod = (u128)u * (u128)m.limbs[j] + t[j] + carry;
            t[j] = (u64)prod;
            carry = (u64)(prod >> 64);
        }
        sum = (u128)t[6] + carry;
        t[6] = (u64)sum;
        t[7] += (u64)(sum >> 64);

        for (int j = 0; j < 7; ++j) t[j] = t[j + 1];
        t[7] = 0;
    }

    U384 r{t[0], t[1], t[2], t[3], t[4], t[5]};
    if (t[6] != 0 || U384::cmp(r, m) >= 0) {
        u64 bw;
        r = sub_384(r, m, bw);
    }
    return r;
}

inline U384 to_mont(const U384& a, const U384& r2,
                    const U384& m, u64 m_inv) noexcept {
    return mont_mul(a, r2, m, m_inv);
}

inline U384 from_mont(const U384& a, const U384& m, u64 m_inv) noexcept {
    constexpr U384 ONE{1, 0, 0, 0, 0, 0};
    return mont_mul(a, ONE, m, m_inv);
}

inline U384 fp_add(const U384& a, const U384& b) noexcept { return mod_add(a, b, P); }
inline U384 fp_sub(const U384& a, const U384& b) noexcept { return mod_sub(a, b, P); }

inline U384 fp_neg(const U384& a) noexcept {
    if (a.is_zero()) return a;
    u64 bw;
    return sub_384(P, a, bw);
}

inline U384 fp_mul(const U384& a, const U384& b) noexcept {
    return mont_mul(a, b, P, P_INV);
}

inline U384 fp_sqr(const U384& a) noexcept {
    return mont_mul(a, a, P, P_INV);
}

// Square-and-multiply over the LE-limb exponent.  Used to compute Fermat
// inversion only -- variable-time but the exponent (p-2) is public.
inline U384 fp_pow(const U384& a_mont, const U384& e) noexcept {
    constexpr U384 ONE_PLAIN{1, 0, 0, 0, 0, 0};
    U384 result = to_mont(ONE_PLAIN, R2_FP, P, P_INV);
    U384 base = a_mont;
    for (int limb = 0; limb < 6; ++limb) {
        u64 w = e.limbs[limb];
        for (int bit = 0; bit < 64; ++bit) {
            if ((w >> bit) & 1) result = fp_mul(result, base);
            base = fp_sqr(base);
        }
    }
    return result;
}

inline U384 fp_inv(const U384& a_mont) noexcept {
    return fp_pow(a_mont, P_M2);
}

inline U384 to_mont_fp(const U384& a) noexcept   { return to_mont(a, R2_FP, P, P_INV); }
inline U384 from_mont_fp(const U384& a) noexcept { return from_mont(a, P, P_INV); }

// b = 4 in Montgomery form (BLS12-381 short-Weierstrass curve constant).
inline U384 fp_four() noexcept {
    return to_mont_fp(U384{4, 0, 0, 0, 0, 0});
}

}  // namespace kinet::crypto::bls12_381

// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// First-party Montgomery field arithmetic for secp256k1.
//   Fp (base field):  y^2 = x^3 + 7 mod p, p = 2^256 - 2^32 - 977
//   Fn (scalar field): n = curve order
//
// Algorithms used:
//   * CIOS Montgomery multiplication.
//   * Fermat inversion: a^(m-2) via square-multiply with addition chain.
//   * Square root via a^((p+1)/4) since p ≡ 3 mod 4.
//
// Header-only so GPU CPU-mode tests can include it.
//
// Limb layout: 4 x uint64_t, little-endian (limbs[0] = least significant).

#pragma once

#include <array>
#include <cstdint>
#include <cstring>

namespace kinet::crypto::secp256k1 {

using u64 = uint64_t;
using u128 = unsigned __int128;

struct U256 {
    u64 limbs[4];

    constexpr U256() : limbs{0,0,0,0} {}
    constexpr U256(u64 l0, u64 l1, u64 l2, u64 l3) : limbs{l0,l1,l2,l3} {}

    bool is_zero() const noexcept {
        return (limbs[0] | limbs[1] | limbs[2] | limbs[3]) == 0;
    }

    static int cmp(const U256& a, const U256& b) noexcept {
        for (int i = 3; i >= 0; --i) {
            if (a.limbs[i] < b.limbs[i]) return -1;
            if (a.limbs[i] > b.limbs[i]) return 1;
        }
        return 0;
    }

    bool operator==(const U256& o) const noexcept { return cmp(*this, o) == 0; }
    bool operator!=(const U256& o) const noexcept { return cmp(*this, o) != 0; }

    static U256 from_be32(const uint8_t b[32]) noexcept {
        U256 r;
        for (int limb = 0; limb < 4; ++limb) {
            u64 v = 0;
            const int base = (3 - limb) * 8;
            for (int i = 0; i < 8; ++i) v = (v << 8) | (u64)b[base + i];
            r.limbs[limb] = v;
        }
        return r;
    }

    void to_be32(uint8_t b[32]) const noexcept {
        for (int limb = 0; limb < 4; ++limb) {
            const int base = (3 - limb) * 8;
            u64 v = limbs[limb];
            for (int i = 7; i >= 0; --i) { b[base + i] = (uint8_t)(v & 0xFF); v >>= 8; }
        }
    }
};

// secp256k1 field prime p = 2^256 - 2^32 - 977
constexpr U256 P{
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};

// Curve order n
constexpr U256 N{
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL};

// Montgomery constants (R = 2^256)
//   R mod p,  R^2 mod p,  -p^-1 mod 2^64
constexpr U256 R_P{0x00000001000003D1ULL, 0, 0, 0};
constexpr U256 R2_P{0x000007A2000E90A1ULL, 0x0000000000000001ULL, 0, 0};
constexpr u64  P_INV = 0xD838091DD2253531ULL;

//   R^2 mod n,  -n^-1 mod 2^64
constexpr U256 R2_N{0x896CF21467D7D140ULL, 0x741496C20E7CF878ULL,
                    0xE697F5E45BCD07C6ULL, 0x9D671CD581C69BC5ULL};
constexpr u64  N_INV = 0x4B0DFF665588B13FULL;

// Generator G in affine, normal form (not Montgomery)
constexpr U256 GX{0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
                  0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL};
constexpr U256 GY{0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
                  0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL};

// ---------------------------------------------------------------------------
// Plain 256-bit arithmetic
// ---------------------------------------------------------------------------

inline U256 add_256(const U256& a, const U256& b, u64& carry) noexcept {
    U256 r;
    u64 c = 0;
    for (int i = 0; i < 4; ++i) {
        u128 t = (u128)a.limbs[i] + (u128)b.limbs[i] + c;
        r.limbs[i] = (u64)t;
        c = (u64)(t >> 64);
    }
    carry = c;
    return r;
}

inline U256 sub_256(const U256& a, const U256& b, u64& borrow) noexcept {
    U256 r;
    u64 bw = 0;
    for (int i = 0; i < 4; ++i) {
        u128 t = (u128)a.limbs[i] - (u128)b.limbs[i] - bw;
        r.limbs[i] = (u64)t;
        bw = (u64)((t >> 64) & 1ULL);
    }
    borrow = bw;
    return r;
}

// Conditionally subtract m from r if r >= m. Returns reduced value.
inline U256 cond_sub(const U256& r, const U256& m) noexcept {
    u64 bw;
    U256 t = sub_256(r, m, bw);
    if (bw == 0 && U256::cmp(r, m) >= 0) return t;
    if (bw == 0) {
        // r < m and no borrow shouldn't happen; but cmp says r < m means t underflowed
        // — fall through to return r.
    }
    return r;
}

// Modular addition: (a + b) mod m
inline U256 mod_add(const U256& a, const U256& b, const U256& m) noexcept {
    u64 c;
    U256 t = add_256(a, b, c);
    if (c != 0 || U256::cmp(t, m) >= 0) {
        u64 bw;
        t = sub_256(t, m, bw);
    }
    return t;
}

// Modular subtraction: (a - b) mod m
inline U256 mod_sub(const U256& a, const U256& b, const U256& m) noexcept {
    u64 bw;
    U256 t = sub_256(a, b, bw);
    if (bw != 0) {
        u64 c;
        t = add_256(t, m, c);
    }
    return t;
}

// ---------------------------------------------------------------------------
// CIOS Montgomery multiplication: r = a * b * R^-1 mod m
// ---------------------------------------------------------------------------

inline U256 mont_mul(const U256& a, const U256& b, const U256& m, u64 m_inv) noexcept {
    u64 t[6] = {0, 0, 0, 0, 0, 0};

    for (int i = 0; i < 4; ++i) {
        // t += a * b[i]
        u64 carry = 0;
        for (int j = 0; j < 4; ++j) {
            u128 prod = (u128)a.limbs[j] * (u128)b.limbs[i] + t[j] + carry;
            t[j] = (u64)prod;
            carry = (u64)(prod >> 64);
        }
        u128 sum = (u128)t[4] + carry;
        t[4] = (u64)sum;
        t[5] += (u64)(sum >> 64);

        // u = t[0] * m_inv mod 2^64
        u64 u = t[0] * m_inv;

        // t += u * m
        carry = 0;
        for (int j = 0; j < 4; ++j) {
            u128 prod = (u128)u * (u128)m.limbs[j] + t[j] + carry;
            t[j] = (u64)prod;
            carry = (u64)(prod >> 64);
        }
        sum = (u128)t[4] + carry;
        t[4] = (u64)sum;
        t[5] += (u64)(sum >> 64);

        // shift right by 64 bits (drop t[0])
        for (int j = 0; j < 5; ++j) t[j] = t[j + 1];
        t[5] = 0;
    }

    U256 r{t[0], t[1], t[2], t[3]};
    if (t[4] != 0 || U256::cmp(r, m) >= 0) {
        u64 bw;
        r = sub_256(r, m, bw);
    }
    return r;
}

inline U256 to_mont(const U256& a, const U256& r2, const U256& m, u64 m_inv) noexcept {
    return mont_mul(a, r2, m, m_inv);
}

inline U256 from_mont(const U256& a, const U256& m, u64 m_inv) noexcept {
    constexpr U256 ONE{1, 0, 0, 0};
    return mont_mul(a, ONE, m, m_inv);
}

// ---------------------------------------------------------------------------
// Fp helpers (Montgomery form throughout)
// ---------------------------------------------------------------------------

inline U256 fp_add(const U256& a, const U256& b) noexcept { return mod_add(a, b, P); }
inline U256 fp_sub(const U256& a, const U256& b) noexcept { return mod_sub(a, b, P); }
inline U256 fp_mul(const U256& a, const U256& b) noexcept { return mont_mul(a, b, P, P_INV); }
inline U256 fp_sqr(const U256& a) noexcept { return mont_mul(a, a, P, P_INV); }

// Fermat exponentiation a^e mod p (e is plain U256, NOT Montgomery)
inline U256 fp_pow(const U256& a_mont, const U256& e) noexcept {
    constexpr U256 ONE_PLAIN{1, 0, 0, 0};
    U256 result = to_mont(ONE_PLAIN, R2_P, P, P_INV);
    U256 base = a_mont;
    for (int limb = 0; limb < 4; ++limb) {
        u64 w = e.limbs[limb];
        for (int bit = 0; bit < 64; ++bit) {
            if ((w >> bit) & 1) result = fp_mul(result, base);
            base = fp_sqr(base);
        }
    }
    return result;
}

// Fp inversion via Fermat: a^(p-2)
inline U256 fp_inv(const U256& a_mont) noexcept {
    // p - 2
    constexpr U256 P_M2{0xFFFFFFFEFFFFFC2DULL, 0xFFFFFFFFFFFFFFFFULL,
                       0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};
    return fp_pow(a_mont, P_M2);
}

// Fp square root: since p ≡ 3 mod 4, sqrt(a) = a^((p+1)/4)
inline bool fp_sqrt(const U256& a_mont, U256& out_mont) noexcept {
    // (p+1)/4
    constexpr U256 PP1_4{0xFFFFFFFFBFFFFF0CULL, 0xFFFFFFFFFFFFFFFFULL,
                        0xFFFFFFFFFFFFFFFFULL, 0x3FFFFFFFFFFFFFFFULL};
    U256 cand = fp_pow(a_mont, PP1_4);
    if (fp_sqr(cand) != a_mont) return false;
    out_mont = cand;
    return true;
}

// ---------------------------------------------------------------------------
// Fn helpers (scalar field)
// ---------------------------------------------------------------------------

inline U256 fn_add(const U256& a, const U256& b) noexcept { return mod_add(a, b, N); }
inline U256 fn_sub(const U256& a, const U256& b) noexcept { return mod_sub(a, b, N); }
inline U256 fn_mul(const U256& a, const U256& b) noexcept { return mont_mul(a, b, N, N_INV); }
inline U256 fn_sqr(const U256& a) noexcept { return mont_mul(a, a, N, N_INV); }

inline U256 fn_pow(const U256& a_mont, const U256& e) noexcept {
    constexpr U256 ONE_PLAIN{1, 0, 0, 0};
    U256 result = to_mont(ONE_PLAIN, R2_N, N, N_INV);
    U256 base = a_mont;
    for (int limb = 0; limb < 4; ++limb) {
        u64 w = e.limbs[limb];
        for (int bit = 0; bit < 64; ++bit) {
            if ((w >> bit) & 1) result = fn_mul(result, base);
            base = fn_sqr(base);
        }
    }
    return result;
}

inline U256 fn_inv(const U256& a_mont) noexcept {
    // n - 2
    constexpr U256 N_M2{0xBFD25E8CD036413FULL, 0xBAAEDCE6AF48A03BULL,
                       0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL};
    return fn_pow(a_mont, N_M2);
}

inline U256 to_mont_p(const U256& a) noexcept { return to_mont(a, R2_P, P, P_INV); }
inline U256 from_mont_p(const U256& a) noexcept { return from_mont(a, P, P_INV); }
inline U256 to_mont_n(const U256& a) noexcept { return to_mont(a, R2_N, N, N_INV); }
inline U256 from_mont_n(const U256& a) noexcept { return from_mont(a, N, N_INV); }

}  // namespace kinet::crypto::secp256k1

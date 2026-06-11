// First-party Montgomery field arithmetic for bn254 (alt_bn128).
//   Fp (base field):  y^2 = x^3 + 3 mod p
//                     p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
//   Fr (scalar field): r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//
// Algorithms used:
//   * CIOS Montgomery multiplication.
//   * Fermat inversion: a^(m-2) via square-multiply.
//   * Square root via a^((p+1)/4) since p ≡ 3 mod 4.
//
// Algorithmic transliteration of the standard Montgomery method as documented
// in Handbook of Applied Cryptography §14.36 and Koc/Acar/Kaliski 1996; this
// file copies no upstream source.
//
// Header-only so GPU CPU-mode tests can include it without linkage.
//
// Limb layout: 4 x uint64_t, little-endian (limbs[0] = least significant).

#pragma once

#include <array>
#include <cstdint>
#include <cstring>

namespace kinet::crypto::bn254 {

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

    bool bit(unsigned i) const noexcept {
        return ((limbs[i >> 6] >> (i & 63)) & 1ULL) != 0;
    }
};

constexpr U256 P{
    0x3C208C16D87CFD47ULL, 0x97816A916871CA8DULL,
    0xB85045B68181585DULL, 0x30644E72E131A029ULL};

constexpr U256 FR_ORDER{
    0x43E1F593F0000001ULL, 0x2833E84879B97091ULL,
    0xB85045B68181585DULL, 0x30644E72E131A029ULL};

constexpr U256 R_FP{
    0xD35D438DC58F0D9DULL, 0x0A78EB28F5C70B3DULL,
    0x666EA36F7879462CULL, 0x0E0A77C19A07DF2FULL};
constexpr U256 R2_FP{
    0xF32CFC5B538AFA89ULL, 0xB5E71911D44501FBULL,
    0x47AB1EFF0A417FF6ULL, 0x06D89F71CAB8351FULL};
constexpr u64  P_INV = 0x87D20782E4866389ULL;

constexpr U256 R_FR{
    0xAC96341C4FFFFFFBULL, 0x36FC76959F60CD29ULL,
    0x666EA36F7879462EULL, 0x0E0A77C19A07DF2FULL};
constexpr U256 R2_FR{
    0x1BB8E645AE216DA7ULL, 0x53FE3AB1E35C59E3ULL,
    0x8C49833D53BB8085ULL, 0x0216D0B17F4E44A5ULL};
constexpr u64  R_INV = 0xC2E1F593EFFFFFFFULL;

constexpr U256 P_M2{
    0x3C208C16D87CFD45ULL, 0x97816A916871CA8DULL,
    0xB85045B68181585DULL, 0x30644E72E131A029ULL};

constexpr U256 FR_M2{
    0x43E1F593EFFFFFFFULL, 0x2833E84879B97091ULL,
    0xB85045B68181585DULL, 0x30644E72E131A029ULL};

constexpr U256 PP1_4{
    0x4F082305B61F3F52ULL, 0x65E05AA45A1C72A3ULL,
    0x6E14116DA0605617ULL, 0x0C19139CB84C680AULL};

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

inline U256 mod_add(const U256& a, const U256& b, const U256& m) noexcept {
    u64 c;
    U256 t = add_256(a, b, c);
    if (c != 0 || U256::cmp(t, m) >= 0) {
        u64 bw;
        t = sub_256(t, m, bw);
    }
    return t;
}

inline U256 mod_sub(const U256& a, const U256& b, const U256& m) noexcept {
    u64 bw;
    U256 t = sub_256(a, b, bw);
    if (bw != 0) {
        u64 c;
        t = add_256(t, m, c);
    }
    return t;
}

inline U256 mont_mul(const U256& a, const U256& b, const U256& m, u64 m_inv) noexcept {
    u64 t[6] = {0, 0, 0, 0, 0, 0};

    for (int i = 0; i < 4; ++i) {
        u64 carry = 0;
        for (int j = 0; j < 4; ++j) {
            u128 prod = (u128)a.limbs[j] * (u128)b.limbs[i] + t[j] + carry;
            t[j] = (u64)prod;
            carry = (u64)(prod >> 64);
        }
        u128 sum = (u128)t[4] + carry;
        t[4] = (u64)sum;
        t[5] += (u64)(sum >> 64);

        u64 u = t[0] * m_inv;

        carry = 0;
        for (int j = 0; j < 4; ++j) {
            u128 prod = (u128)u * (u128)m.limbs[j] + t[j] + carry;
            t[j] = (u64)prod;
            carry = (u64)(prod >> 64);
        }
        sum = (u128)t[4] + carry;
        t[4] = (u64)sum;
        t[5] += (u64)(sum >> 64);

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

inline U256 fp_add(const U256& a, const U256& b) noexcept { return mod_add(a, b, P); }
inline U256 fp_sub(const U256& a, const U256& b) noexcept { return mod_sub(a, b, P); }
inline U256 fp_neg(const U256& a) noexcept {
    if (a.is_zero()) return a;
    u64 bw;
    return sub_256(P, a, bw);
}
inline U256 fp_mul(const U256& a, const U256& b) noexcept { return mont_mul(a, b, P, P_INV); }
inline U256 fp_sqr(const U256& a) noexcept { return mont_mul(a, a, P, P_INV); }

inline U256 fp_pow(const U256& a_mont, const U256& e) noexcept {
    constexpr U256 ONE_PLAIN{1, 0, 0, 0};
    U256 result = to_mont(ONE_PLAIN, R2_FP, P, P_INV);
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

inline U256 fp_inv(const U256& a_mont) noexcept {
    return fp_pow(a_mont, P_M2);
}

inline bool fp_sqrt(const U256& a_mont, U256& out_mont) noexcept {
    U256 cand = fp_pow(a_mont, PP1_4);
    if (fp_sqr(cand) != a_mont) return false;
    out_mont = cand;
    return true;
}

inline U256 fr_add(const U256& a, const U256& b) noexcept { return mod_add(a, b, FR_ORDER); }
inline U256 fr_sub(const U256& a, const U256& b) noexcept { return mod_sub(a, b, FR_ORDER); }
inline U256 fr_mul(const U256& a, const U256& b) noexcept { return mont_mul(a, b, FR_ORDER, R_INV); }
inline U256 fr_sqr(const U256& a) noexcept { return mont_mul(a, a, FR_ORDER, R_INV); }

inline U256 fr_pow(const U256& a_mont, const U256& e) noexcept {
    constexpr U256 ONE_PLAIN{1, 0, 0, 0};
    U256 result = to_mont(ONE_PLAIN, R2_FR, FR_ORDER, R_INV);
    U256 base = a_mont;
    for (int limb = 0; limb < 4; ++limb) {
        u64 w = e.limbs[limb];
        for (int bit = 0; bit < 64; ++bit) {
            if ((w >> bit) & 1) result = fr_mul(result, base);
            base = fr_sqr(base);
        }
    }
    return result;
}

inline U256 fr_inv(const U256& a_mont) noexcept {
    return fr_pow(a_mont, FR_M2);
}

inline U256 to_mont_fp(const U256& a) noexcept { return to_mont(a, R2_FP, P, P_INV); }
inline U256 from_mont_fp(const U256& a) noexcept { return from_mont(a, P, P_INV); }
inline U256 to_mont_fr(const U256& a) noexcept { return to_mont(a, R2_FR, FR_ORDER, R_INV); }
inline U256 from_mont_fr(const U256& a) noexcept { return from_mont(a, FR_ORDER, R_INV); }

inline U256 fp_three() noexcept {
    return to_mont_fp(U256{3, 0, 0, 0});
}

}  // namespace kinet::crypto::bn254

// BN254 scalar field (Fr) arithmetic. Standard (non-Montgomery)
// representation — operates on 4-limb little-endian uint64_t. Multiplications
// use 128-bit intermediate products via __uint128_t (or msvc _umul128 on
// Windows, but we are kinet-labs/C++20 + clang/gcc).
//
// Modulus r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//          = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
//
// Functions:
//   from_bytes_be:  parse 32 BE bytes; returns false if value >= r.
//   to_bytes_be:    serialize 4 limbs to 32 BE bytes.
//   add, sub, neg:  trivial mod-r additions/subtractions.
//   mul:            schoolbook mul + Barrett-style reduction via shift+sub.

#pragma once
#include <cstdint>
#include <cstring>

namespace kinet::crypto::poseidon::fr {

// Field modulus (little-endian limbs).
//   r = 0x30644e72e131a029_b85045b68181585d_2833e84879b97091_43e1f593f0000001
constexpr uint64_t MOD[4] = {
    0x43e1f593f0000001ULL,
    0x2833e84879b97091ULL,
    0xb85045b68181585dULL,
    0x30644e72e131a029ULL,
};

// 2*r
constexpr uint64_t MOD2[4] = {
    0x87c3eb27e0000002ULL,
    0x5067d090f372e122ULL,
    0x70a08b6d0302b0baULL,
    0x60c89ce4c2634053ULL,
};

inline bool ge_mod(const uint64_t a[4]) noexcept {
    for (int i = 3; i >= 0; --i) {
        if (a[i] != MOD[i]) return a[i] > MOD[i];
    }
    return true;
}

inline bool ge(const uint64_t a[4], const uint64_t b[4]) noexcept {
    for (int i = 3; i >= 0; --i) {
        if (a[i] != b[i]) return a[i] > b[i];
    }
    return true;
}

inline void sub_inplace(uint64_t a[4], const uint64_t b[4]) noexcept {
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        unsigned __int128 t = (unsigned __int128)a[i] - b[i] - borrow;
        a[i] = (uint64_t)t;
        borrow = (t >> 64) & 1ULL;  // 1 if underflow
    }
}

// Returns the carry out of an unsigned 4-limb add.
inline uint64_t add_carry(uint64_t r_[4], const uint64_t a[4],
                          const uint64_t b[4]) noexcept {
    uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        unsigned __int128 t = (unsigned __int128)a[i] + b[i] + carry;
        r_[i] = (uint64_t)t;
        carry = (uint64_t)(t >> 64);
    }
    return carry;
}

// Mod-r addition: r = (a + b) mod p.
inline void add_mod(uint64_t r_[4], const uint64_t a[4],
                    const uint64_t b[4]) noexcept {
    uint64_t c = add_carry(r_, a, b);
    if (c || ge_mod(r_)) {
        sub_inplace(r_, MOD);
    }
}

// Mod-r subtraction: r = (a - b) mod p.
inline void sub_mod(uint64_t r_[4], const uint64_t a[4],
                    const uint64_t b[4]) noexcept {
    if (ge(a, b)) {
        // a - b without borrow.
        uint64_t borrow = 0;
        for (int i = 0; i < 4; ++i) {
            unsigned __int128 t = (unsigned __int128)a[i] - b[i] - borrow;
            r_[i] = (uint64_t)t;
            borrow = (t >> 64) & 1ULL;
        }
    } else {
        // p - b + a (since b > a).
        uint64_t tmp[4];
        uint64_t borrow = 0;
        for (int i = 0; i < 4; ++i) {
            unsigned __int128 t = (unsigned __int128)MOD[i] - b[i] - borrow;
            tmp[i] = (uint64_t)t;
            borrow = (t >> 64) & 1ULL;
        }
        // r = tmp + a (won't exceed 2*p, may exceed p).
        uint64_t carry = add_carry(r_, tmp, a);
        if (carry || ge_mod(r_)) sub_inplace(r_, MOD);
    }
}

inline void double_mod(uint64_t r_[4], const uint64_t a[4]) noexcept {
    add_mod(r_, a, a);
}

// Schoolbook 256x256 -> 512-bit multiply.
inline void mul_512(uint64_t out[8], const uint64_t a[4],
                    const uint64_t b[4]) noexcept {
    for (int k = 0; k < 8; ++k) out[k] = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            unsigned __int128 t =
                (unsigned __int128)a[i] * b[j]
                + (unsigned __int128)out[i + j]
                + (unsigned __int128)carry;
            out[i + j] = (uint64_t)t;
            carry = (uint64_t)(t >> 64);
        }
        out[i + 4] = carry;
    }
}

// Slow but straightforward modular reduction: r = wide mod MOD.
// Uses long division by repeated shift-and-subtract. 256-bit result needs
// at most 256 iterations; we observe a much tighter loop suffices since the
// quotient fits in 4 limbs.
inline void reduce_512(uint64_t r_[4], const uint64_t wide[8]) noexcept {
    // Initialize r_ = wide[7..4] (high 256 bits).
    uint64_t hi[4] = { wide[4], wide[5], wide[6], wide[7] };
    uint64_t lo[4] = { wide[0], wide[1], wide[2], wide[3] };

    // Reduce hi mod MOD using the identity:
    //   wide = hi * 2^256 + lo
    //   2^256 = 2*r - (2*r - 2^256) = ... not straightforward
    // Just use bit-by-bit shift-subtract: process 256 bits of `hi` and `lo`.
    // Result accumulates in r_.
    uint64_t acc[4] = {0, 0, 0, 0};

    auto shl1_with_in = [&](uint64_t x) {
        // shift acc left by 1, OR-in x's high bit
        uint64_t carry = x;
        for (int i = 0; i < 4; ++i) {
            uint64_t next = (acc[i] >> 63) & 1ULL;
            acc[i] = (acc[i] << 1) | carry;
            carry = next;
        }
        // bits beyond 256 implicitly drop (but we condition on subtraction)
        return carry;  // overflow bit
    };

    // 8 limbs * 64 bits = 512 bits, MSB first.
    for (int word = 7; word >= 0; --word) {
        uint64_t w = (word >= 4) ? hi[word - 4] : lo[word];
        for (int bit = 63; bit >= 0; --bit) {
            uint64_t b = (w >> bit) & 1ULL;
            uint64_t ovf = shl1_with_in(b);
            if (ovf || ge_mod(acc)) {
                sub_inplace(acc, MOD);
            }
        }
    }
    for (int i = 0; i < 4; ++i) r_[i] = acc[i];
}

inline void mul_mod(uint64_t r_[4], const uint64_t a[4],
                    const uint64_t b[4]) noexcept {
    uint64_t wide[8];
    mul_512(wide, a, b);
    reduce_512(r_, wide);
}

inline void square_mod(uint64_t r_[4], const uint64_t a[4]) noexcept {
    mul_mod(r_, a, a);
}

// x^5 = x^2 * x^2 * x.
inline void pow5_mod(uint64_t r_[4], const uint64_t a[4]) noexcept {
    uint64_t a2[4], a4[4];
    square_mod(a2, a);
    square_mod(a4, a2);
    mul_mod(r_, a4, a);
}

// Big-endian 32 bytes -> 4 little-endian limbs.
// Returns false if the parsed value is >= MOD (i.e. not canonical).
inline bool from_bytes_be(uint64_t r_[4], const uint8_t bytes[32]) noexcept {
    for (int i = 0; i < 4; ++i) {
        // bytes[0..7] = limb 3 (most significant), bytes[24..31] = limb 0.
        const uint8_t* p = bytes + (3 - i) * 8;
        r_[i] = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
                ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
                ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
                ((uint64_t)p[6] <<  8) | ((uint64_t)p[7]);
    }
    return !ge_mod(r_);
}

inline void to_bytes_be(uint8_t out[32], const uint64_t a[4]) noexcept {
    for (int i = 0; i < 4; ++i) {
        uint64_t w = a[3 - i];
        uint8_t* p = out + i * 8;
        p[0] = uint8_t(w >> 56);
        p[1] = uint8_t(w >> 48);
        p[2] = uint8_t(w >> 40);
        p[3] = uint8_t(w >> 32);
        p[4] = uint8_t(w >> 24);
        p[5] = uint8_t(w >> 16);
        p[6] = uint8_t(w >> 8);
        p[7] = uint8_t(w);
    }
}

// Parse from hex string ("0x..." prefix optional) into 4 little-endian limbs.
// Used by the round-key initializer to bake constants from the json file.
inline bool from_hex_be(uint64_t r_[4], const char* s) noexcept {
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    uint8_t bytes[32] = {0};
    int len = 0;
    while (s[len] != '\0') ++len;
    if (len > 64) return false;
    int pad = 64 - len;
    auto h = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (int i = 0; i < len; ++i) {
        int v = h(s[i]);
        if (v < 0) return false;
        int dst = (pad + i) / 2;
        if ((pad + i) % 2 == 0) bytes[dst] = uint8_t(v << 4);
        else bytes[dst] |= uint8_t(v);
    }
    return from_bytes_be(r_, bytes);
}

}  // namespace kinet::crypto::poseidon::fr

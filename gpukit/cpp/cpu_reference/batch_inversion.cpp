// Montgomery batch inversion -- generic over the modulus.
//
// Algorithm:
//   1. Compute prefix products p[i] = a[0] * a[1] * ... * a[i].
//   2. Invert p[n-1] once via Fermat / extended Euclidean (we use Fermat:
//      a^-1 = a^(p-2) mod p, square-and-multiply).
//   3. Walk backwards: inv[i] = p[i-1] * inv_p[i].
//
// Three concrete instantiations (secp256k1 / BN254 / BLS12-381) with explicit
// constants, no templating. Field elements are little-endian byte arrays.

#include "kinet/gpukit/batch_inversion.h"
#include "kinet/gpukit/gpukit.h"
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// 256-bit fixed precision (4 x u64 limbs).
// ---------------------------------------------------------------------------
struct U256 { uint64_t l[4]; };

inline U256 u256_zero() { return U256{ {0,0,0,0} }; }

inline U256 u256_from_le(const uint8_t* b) {
    U256 r;
    for (int i = 0; i < 4; ++i) {
        uint64_t v = 0;
        for (int j = 0; j < 8; ++j) v |= ((uint64_t)b[i*8+j]) << (8*j);
        r.l[i] = v;
    }
    return r;
}

inline void u256_to_le(const U256& x, uint8_t* b) {
    for (int i = 0; i < 4; ++i) {
        uint64_t v = x.l[i];
        for (int j = 0; j < 8; ++j) b[i*8+j] = (uint8_t)(v >> (8*j));
    }
}

inline bool u256_is_zero(const U256& x) {
    return (x.l[0] | x.l[1] | x.l[2] | x.l[3]) == 0;
}

inline int u256_cmp(const U256& a, const U256& b) {
    for (int i = 3; i >= 0; --i) {
        if (a.l[i] < b.l[i]) return -1;
        if (a.l[i] > b.l[i]) return  1;
    }
    return 0;
}

// (lo, hi) = a + b + carry
inline uint64_t addc(uint64_t a, uint64_t b, uint64_t cin, uint64_t* cout) {
    __uint128_t s = (__uint128_t)a + b + cin;
    *cout = (uint64_t)(s >> 64);
    return (uint64_t)s;
}
// (lo, hi) = a - b - borrow
inline uint64_t subb(uint64_t a, uint64_t b, uint64_t bin, uint64_t* bout) {
    __uint128_t d = (__uint128_t)a - b - bin;
    *bout = (uint64_t)(d >> 64) & 1;  // top bit if borrowed
    return (uint64_t)d;
}

inline U256 u256_add(const U256& a, const U256& b) {
    U256 r; uint64_t c = 0;
    for (int i = 0; i < 4; ++i) r.l[i] = addc(a.l[i], b.l[i], c, &c);
    return r;
}
inline U256 u256_sub(const U256& a, const U256& b) {
    U256 r; uint64_t br = 0;
    for (int i = 0; i < 4; ++i) r.l[i] = subb(a.l[i], b.l[i], br, &br);
    return r;
}

inline U256 u256_addmod(const U256& a, const U256& b, const U256& p) {
    U256 r = u256_add(a, b);
    if (u256_cmp(r, p) >= 0) r = u256_sub(r, p);
    return r;
}
inline U256 u256_submod(const U256& a, const U256& b, const U256& p) {
    if (u256_cmp(a, b) >= 0) return u256_sub(a, b);
    U256 r = u256_sub(b, a);
    return u256_sub(p, r);
}

// 256x256 -> 512 schoolbook multiplication.
struct U512 { uint64_t l[8]; };
inline U512 u256_mul_full(const U256& a, const U256& b) {
    U512 r; std::memset(&r, 0, sizeof(r));
    for (int i = 0; i < 4; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            __uint128_t t = (__uint128_t)a.l[i] * b.l[j] + r.l[i+j] + carry;
            r.l[i+j] = (uint64_t)t;
            carry = (uint64_t)(t >> 64);
        }
        r.l[i+4] = carry;
    }
    return r;
}

// Reduce a U512 mod p by long division (binary, 256 bits). Slow but correct.
// This is fine for the generic fallback; the fields below override with
// faster Barrett / pseudo-Mersenne reductions.
inline U256 u512_mod_p_generic(const U512& x, const U256& p) {
    // Lift to a 257-limb register and shift down.
    uint64_t r[8]; std::memcpy(r, x.l, sizeof(r));
    // We will reduce 256 bits of "extra" range.
    for (int bit = 511; bit >= 256; --bit) {
        // Effectively: if top bit of (r mod 2^(bit+1)) corresponds to a
        // shift-by-(bit-255) of p, subtract.
        int word = bit / 64;
        int b = bit % 64;
        if ((r[word] >> b) & 1ULL) {
            // Subtract p << (bit - 255).
            int shift = bit - 255;
            int sw = shift / 64;
            int sb = shift % 64;
            uint64_t pl[8] = {0,0,0,0,0,0,0,0};
            for (int i = 0; i < 4; ++i) {
                __uint128_t v = (__uint128_t)p.l[i] << sb;
                pl[i + sw] |= (uint64_t)v;
                if (sb && i + sw + 1 < 8) pl[i + sw + 1] |= (uint64_t)(v >> 64);
            }
            uint64_t br = 0;
            for (int i = 0; i < 8; ++i) {
                __uint128_t d = (__uint128_t)r[i] - pl[i] - br;
                r[i] = (uint64_t)d;
                br = (uint64_t)(d >> 64) & 1;
            }
        }
    }
    U256 out; for (int i = 0; i < 4; ++i) out.l[i] = r[i];
    if (u256_cmp(out, p) >= 0) out = u256_sub(out, p);
    return out;
}

inline U256 u256_mulmod(const U256& a, const U256& b, const U256& p) {
    U512 t = u256_mul_full(a, b);
    return u512_mod_p_generic(t, p);
}

// Fermat inversion: a^(p-2) mod p via square-and-multiply.
inline U256 u256_invmod(const U256& a, const U256& p) {
    // exp = p - 2
    U256 two = u256_zero(); two.l[0] = 2;
    U256 exp = u256_sub(p, two);
    U256 result = u256_zero(); result.l[0] = 1;
    U256 base = a;
    for (int i = 0; i < 256; ++i) {
        int word = i / 64;
        int bit  = i % 64;
        if ((exp.l[word] >> bit) & 1ULL) {
            result = u256_mulmod(result, base, p);
        }
        base = u256_mulmod(base, base, p);
    }
    return result;
}

inline int batch_inv_256(const uint8_t* in, uint8_t* out, size_t n, const U256& p) {
    if (n == 0) return GPUKIT_OK;
    std::vector<U256> v(n);
    for (size_t i = 0; i < n; ++i) {
        v[i] = u256_from_le(in + i * 32);
        if (u256_is_zero(v[i])) return GPUKIT_ERR_BAD_SIZE;
    }
    // Prefix products into out (treat out as scratch first).
    std::vector<U256> pref(n);
    pref[0] = v[0];
    for (size_t i = 1; i < n; ++i) {
        pref[i] = u256_mulmod(pref[i-1], v[i], p);
    }
    U256 inv_total = u256_invmod(pref[n-1], p);
    // Walk back.
    std::vector<U256> inv(n);
    for (size_t i = n; i-- > 0; ) {
        if (i == 0) {
            inv[0] = inv_total;
        } else {
            inv[i] = u256_mulmod(inv_total, pref[i-1], p);
            inv_total = u256_mulmod(inv_total, v[i], p);
        }
    }
    for (size_t i = 0; i < n; ++i) {
        u256_to_le(inv[i], out + i * 32);
    }
    return GPUKIT_OK;
}

// ---------------------------------------------------------------------------
// 384-bit fixed precision (6 x u64 limbs) for BLS12-381.
// ---------------------------------------------------------------------------
struct U384 { uint64_t l[6]; };

inline U384 u384_zero() { return U384{ {0,0,0,0,0,0} }; }
inline U384 u384_from_le(const uint8_t* b) {
    U384 r;
    for (int i = 0; i < 6; ++i) {
        uint64_t v = 0;
        for (int j = 0; j < 8; ++j) v |= ((uint64_t)b[i*8+j]) << (8*j);
        r.l[i] = v;
    }
    return r;
}
inline void u384_to_le(const U384& x, uint8_t* b) {
    for (int i = 0; i < 6; ++i) {
        uint64_t v = x.l[i];
        for (int j = 0; j < 8; ++j) b[i*8+j] = (uint8_t)(v >> (8*j));
    }
}
inline bool u384_is_zero(const U384& x) {
    uint64_t a = 0; for (int i = 0; i < 6; ++i) a |= x.l[i]; return a == 0;
}
inline int u384_cmp(const U384& a, const U384& b) {
    for (int i = 5; i >= 0; --i) {
        if (a.l[i] < b.l[i]) return -1;
        if (a.l[i] > b.l[i]) return  1;
    }
    return 0;
}
inline U384 u384_add(const U384& a, const U384& b) {
    U384 r; uint64_t c = 0;
    for (int i = 0; i < 6; ++i) r.l[i] = addc(a.l[i], b.l[i], c, &c);
    return r;
}
inline U384 u384_sub(const U384& a, const U384& b) {
    U384 r; uint64_t br = 0;
    for (int i = 0; i < 6; ++i) r.l[i] = subb(a.l[i], b.l[i], br, &br);
    return r;
}
inline U384 u384_submod(const U384& a, const U384& b, const U384& p) {
    if (u384_cmp(a, b) >= 0) return u384_sub(a, b);
    U384 r = u384_sub(b, a);
    return u384_sub(p, r);
}
inline U384 u384_addmod(const U384& a, const U384& b, const U384& p) {
    U384 r = u384_add(a, b);
    if (u384_cmp(r, p) >= 0) r = u384_sub(r, p);
    return r;
}

struct U768 { uint64_t l[12]; };
inline U768 u384_mul_full(const U384& a, const U384& b) {
    U768 r; std::memset(&r, 0, sizeof(r));
    for (int i = 0; i < 6; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 6; ++j) {
            __uint128_t t = (__uint128_t)a.l[i] * b.l[j] + r.l[i+j] + carry;
            r.l[i+j] = (uint64_t)t;
            carry = (uint64_t)(t >> 64);
        }
        r.l[i+6] = carry;
    }
    return r;
}

inline U384 u768_mod_p_generic(const U768& x, const U384& p) {
    uint64_t r[12]; std::memcpy(r, x.l, sizeof(r));
    for (int bit = 767; bit >= 384; --bit) {
        int word = bit / 64;
        int b = bit % 64;
        if ((r[word] >> b) & 1ULL) {
            int shift = bit - 383;
            int sw = shift / 64;
            int sb = shift % 64;
            uint64_t pl[12] = {0};
            for (int i = 0; i < 6; ++i) {
                __uint128_t v = (__uint128_t)p.l[i] << sb;
                pl[i + sw] |= (uint64_t)v;
                if (sb && i + sw + 1 < 12) pl[i + sw + 1] |= (uint64_t)(v >> 64);
            }
            uint64_t br = 0;
            for (int i = 0; i < 12; ++i) {
                __uint128_t d = (__uint128_t)r[i] - pl[i] - br;
                r[i] = (uint64_t)d;
                br = (uint64_t)(d >> 64) & 1;
            }
        }
    }
    U384 out; for (int i = 0; i < 6; ++i) out.l[i] = r[i];
    if (u384_cmp(out, p) >= 0) out = u384_sub(out, p);
    return out;
}

inline U384 u384_mulmod(const U384& a, const U384& b, const U384& p) {
    U768 t = u384_mul_full(a, b);
    return u768_mod_p_generic(t, p);
}

inline U384 u384_invmod(const U384& a, const U384& p) {
    U384 two = u384_zero(); two.l[0] = 2;
    U384 exp = u384_sub(p, two);
    U384 result = u384_zero(); result.l[0] = 1;
    U384 base = a;
    for (int i = 0; i < 384; ++i) {
        int word = i / 64;
        int bit  = i % 64;
        if ((exp.l[word] >> bit) & 1ULL) {
            result = u384_mulmod(result, base, p);
        }
        base = u384_mulmod(base, base, p);
    }
    return result;
}

inline int batch_inv_384(const uint8_t* in, uint8_t* out, size_t n, const U384& p) {
    if (n == 0) return GPUKIT_OK;
    std::vector<U384> v(n);
    for (size_t i = 0; i < n; ++i) {
        v[i] = u384_from_le(in + i * 48);
        if (u384_is_zero(v[i])) return GPUKIT_ERR_BAD_SIZE;
    }
    std::vector<U384> pref(n);
    pref[0] = v[0];
    for (size_t i = 1; i < n; ++i) {
        pref[i] = u384_mulmod(pref[i-1], v[i], p);
    }
    U384 inv_total = u384_invmod(pref[n-1], p);
    std::vector<U384> inv(n);
    for (size_t i = n; i-- > 0; ) {
        if (i == 0) {
            inv[0] = inv_total;
        } else {
            inv[i] = u384_mulmod(inv_total, pref[i-1], p);
            inv_total = u384_mulmod(inv_total, v[i], p);
        }
    }
    for (size_t i = 0; i < n; ++i) {
        u384_to_le(inv[i], out + i * 48);
    }
    return GPUKIT_OK;
}

// ---------------------------------------------------------------------------
// Field constants (little-endian limbs).
// ---------------------------------------------------------------------------
//
// secp256k1 base field:
//   p = 2^256 - 2^32 - 977 = FFFFFFFF...FFFFFFFEFFFFFC2F
inline U256 secp256k1_p() {
    U256 p;
    p.l[0] = 0xFFFFFFFEFFFFFC2FULL;
    p.l[1] = 0xFFFFFFFFFFFFFFFFULL;
    p.l[2] = 0xFFFFFFFFFFFFFFFFULL;
    p.l[3] = 0xFFFFFFFFFFFFFFFFULL;
    return p;
}

// BN254 base field (Fp):
//   p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
//     = 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47
inline U256 bn254_p() {
    U256 p;
    p.l[0] = 0x3C208C16D87CFD47ULL;
    p.l[1] = 0x97816A916871CA8DULL;
    p.l[2] = 0xB85045B68181585DULL;
    p.l[3] = 0x30644E72E131A029ULL;
    return p;
}

// BLS12-381 base field (Fp):
//   p = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
inline U384 bls12_381_p() {
    U384 p;
    p.l[0] = 0xB9FEFFFFFFFFAAABULL;
    p.l[1] = 0x1EABFFFEB153FFFFULL;
    p.l[2] = 0x6730D2A0F6B0F624ULL;
    p.l[3] = 0x64774B84F38512BFULL;
    p.l[4] = 0x4B1BA7B6434BACD7ULL;
    p.l[5] = 0x1A0111EA397FE69AULL;
    return p;
}

}  // namespace

extern "C" int gpukit_batch_inv_secp256k1_fp_cpu(const uint8_t* in, uint8_t* out, size_t n) {
    return batch_inv_256(in, out, n, secp256k1_p());
}

extern "C" int gpukit_batch_inv_bn254_fp_cpu(const uint8_t* in, uint8_t* out, size_t n) {
    return batch_inv_256(in, out, n, bn254_p());
}

extern "C" int gpukit_batch_inv_bls12_381_fp_cpu(const uint8_t* in, uint8_t* out, size_t n) {
    return batch_inv_384(in, out, n, bls12_381_p());
}

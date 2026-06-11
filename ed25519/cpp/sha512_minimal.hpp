// Minimal SHA-512 (FIPS 180-4) used internally by ed25519-donna's
// CUSTOMHASH path. No OpenSSL, no CommonCrypto. Header-only so it
// compiles into the same TU as ed25519.c.
//
// This is a faithful port of the FIPS 180-4 §6.4 specification, byte-equal
// to OpenSSL / CommonCrypto / RFC 6234 reference output for any input.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace kinet::crypto::ed25519::detail {

struct Sha512Ctx {
    uint64_t H[8];      // chaining state
    uint64_t length;    // total message length in bits
    uint8_t  buf[128];  // partial 1024-bit block
    size_t   used;      // bytes pending in buf
};

inline uint64_t rotr64(uint64_t x, unsigned r) {
    return (x >> r) | (x << (64 - r));
}

inline uint64_t load_be64(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] <<  8) | ((uint64_t)p[7]);
}

inline void store_be64(uint8_t* p, uint64_t v) {
    p[0] = uint8_t(v >> 56); p[1] = uint8_t(v >> 48);
    p[2] = uint8_t(v >> 40); p[3] = uint8_t(v >> 32);
    p[4] = uint8_t(v >> 24); p[5] = uint8_t(v >> 16);
    p[6] = uint8_t(v >>  8); p[7] = uint8_t(v);
}

// First 64 bits of the fractional parts of the cube roots of the first
// 80 primes (FIPS 180-4 §4.2.3).
inline constexpr uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

inline void sha512_compress(Sha512Ctx& s, const uint8_t* block) {
    uint64_t W[80];
    for (int t = 0; t < 16; ++t) W[t] = load_be64(block + 8 * t);
    for (int t = 16; t < 80; ++t) {
        uint64_t s0 = rotr64(W[t-15], 1) ^ rotr64(W[t-15], 8) ^ (W[t-15] >> 7);
        uint64_t s1 = rotr64(W[t-2], 19) ^ rotr64(W[t-2], 61) ^ (W[t-2] >> 6);
        W[t] = W[t-16] + s0 + W[t-7] + s1;
    }

    uint64_t a = s.H[0], b = s.H[1], c = s.H[2], d = s.H[3];
    uint64_t e = s.H[4], f = s.H[5], g = s.H[6], h = s.H[7];

    for (int t = 0; t < 80; ++t) {
        uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t T1 = h + S1 + ch + K[t] + W[t];
        uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t T2 = S0 + mj;
        h = g; g = f; f = e;
        e = d + T1;
        d = c; c = b; b = a;
        a = T1 + T2;
    }

    s.H[0] += a; s.H[1] += b; s.H[2] += c; s.H[3] += d;
    s.H[4] += e; s.H[5] += f; s.H[6] += g; s.H[7] += h;
}

inline void sha512_init(Sha512Ctx& s) {
    // Initial hash values: first 64 bits of the fractional parts of the
    // square roots of the first 8 primes (FIPS 180-4 §5.3.5).
    s.H[0] = 0x6a09e667f3bcc908ULL; s.H[1] = 0xbb67ae8584caa73bULL;
    s.H[2] = 0x3c6ef372fe94f82bULL; s.H[3] = 0xa54ff53a5f1d36f1ULL;
    s.H[4] = 0x510e527fade682d1ULL; s.H[5] = 0x9b05688c2b3e6c1fULL;
    s.H[6] = 0x1f83d9abfb41bd6bULL; s.H[7] = 0x5be0cd19137e2179ULL;
    s.length = 0;
    s.used = 0;
}

inline void sha512_update(Sha512Ctx& s, const uint8_t* data, size_t len) {
    s.length += uint64_t(len) * 8;
    while (len > 0) {
        size_t take = 128 - s.used;
        if (take > len) take = len;
        std::memcpy(s.buf + s.used, data, take);
        s.used += take;
        data   += take;
        len    -= take;
        if (s.used == 128) {
            sha512_compress(s, s.buf);
            s.used = 0;
        }
    }
}

inline void sha512_final(Sha512Ctx& s, uint8_t out[64]) {
    // FIPS 180-4 §5.1.2 padding: 1 bit, then zeroes, then 128-bit length BE.
    s.buf[s.used++] = 0x80;
    if (s.used > 112) {
        std::memset(s.buf + s.used, 0, 128 - s.used);
        sha512_compress(s, s.buf);
        s.used = 0;
    }
    std::memset(s.buf + s.used, 0, 112 - s.used);
    // High 64 bits of the 128-bit length field are always 0 here (we never
    // hash 2^64 bits in a single call). Encode the low 64 bits BE.
    store_be64(s.buf + 112, 0);
    store_be64(s.buf + 120, s.length);
    sha512_compress(s, s.buf);

    for (int i = 0; i < 8; ++i) store_be64(out + 8 * i, s.H[i]);
}

inline void sha512(const uint8_t* data, size_t len, uint8_t out[64]) {
    Sha512Ctx s;
    sha512_init(s);
    sha512_update(s, data, len);
    sha512_final(s, out);
}

} // namespace kinet::crypto::ed25519::detail

// First-party ChaCha20-Poly1305 (RFC 8439) implementation.
//
// All constants and logic derived from RFC 8439. No vendored code.

#include "aead.hpp"

#include <cstring>

namespace kinet::crypto::aead {

// ===========================================================================
// Endianness helpers (RFC 8439 uses little-endian throughout)
// ===========================================================================
namespace {

inline uint32_t load32_le(const uint8_t* p) noexcept {
    return  (uint32_t)p[0]
         | ((uint32_t)p[1] <<  8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

inline void store32_le(uint8_t* p, uint32_t v) noexcept {
    p[0] = (uint8_t)(v      );
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

inline void store64_le(uint8_t* p, uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i));
}

inline uint32_t rotl32(uint32_t x, int n) noexcept {
    return (x << n) | (x >> (32 - n));
}

}  // namespace

// ===========================================================================
// ChaCha20 (RFC 8439 §2.3)
// ===========================================================================
namespace chacha20 {

// "expand 32-byte k" constants (RFC 8439 §2.3, the four-word "sigma").
constexpr uint32_t SIGMA[4] = {
    0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
};

// One quarter-round (RFC 8439 §2.1).
inline void quarterround(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) noexcept {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

void block(const uint8_t key[32], const uint8_t nonce[12],
           uint32_t counter, uint8_t out[64]) noexcept {
    uint32_t s[16];
    s[ 0] = SIGMA[0];          s[ 1] = SIGMA[1];
    s[ 2] = SIGMA[2];          s[ 3] = SIGMA[3];
    s[ 4] = load32_le(key + 0);  s[ 5] = load32_le(key + 4);
    s[ 6] = load32_le(key + 8);  s[ 7] = load32_le(key + 12);
    s[ 8] = load32_le(key + 16); s[ 9] = load32_le(key + 20);
    s[10] = load32_le(key + 24); s[11] = load32_le(key + 28);
    s[12] = counter;
    s[13] = load32_le(nonce + 0);
    s[14] = load32_le(nonce + 4);
    s[15] = load32_le(nonce + 8);

    uint32_t v[16];
    for (int i = 0; i < 16; ++i) v[i] = s[i];

    // 20 rounds = 10 column + 10 diagonal (RFC 8439 §2.3.1).
    for (int i = 0; i < 10; ++i) {
        // Column rounds.
        quarterround(v[0], v[4], v[ 8], v[12]);
        quarterround(v[1], v[5], v[ 9], v[13]);
        quarterround(v[2], v[6], v[10], v[14]);
        quarterround(v[3], v[7], v[11], v[15]);
        // Diagonal rounds.
        quarterround(v[0], v[5], v[10], v[15]);
        quarterround(v[1], v[6], v[11], v[12]);
        quarterround(v[2], v[7], v[ 8], v[13]);
        quarterround(v[3], v[4], v[ 9], v[14]);
    }

    for (int i = 0; i < 16; ++i) {
        store32_le(out + i * 4, v[i] + s[i]);
    }
}

void xor_stream(const uint8_t key[32], const uint8_t nonce[12],
                uint32_t counter, const uint8_t* in, size_t len,
                uint8_t* out) noexcept {
    uint8_t ks[64];
    size_t off = 0;
    while (len > 0) {
        block(key, nonce, counter, ks);
        const size_t take = len < 64 ? len : 64;
        for (size_t i = 0; i < take; ++i) {
            out[off + i] = (in ? in[off + i] : 0) ^ ks[i];
        }
        off += take;
        len -= take;
        ++counter;
    }
}

}  // namespace chacha20

// ===========================================================================
// Poly1305 (RFC 8439 §2.5)
// ===========================================================================
//
// Implementation note: we operate on the 130-bit accumulator using 5 limbs
// of 26 bits each (radix 2^26). This is the standard "donna" decomposition;
// it is portable, side-channel friendly (no secret-dependent branches in
// the hot loop), and matches the math in the RFC exactly.
namespace poly1305 {

// Initialize state from 32-byte key.
void init(State& st, const uint8_t key[32]) noexcept {
    // r = clamp(key[0..16]) per RFC 8439 §2.5.
    const uint32_t r0 = load32_le(key + 0);
    const uint32_t r1 = load32_le(key + 4);
    const uint32_t r2 = load32_le(key + 8);
    const uint32_t r3 = load32_le(key + 12);
    // Clamp: clear high 4 bits of every 32-bit word, and clear bottom 2
    // bits of words 1, 2, 3.
    const uint32_t c0 =  r0       & 0x0fffffff;
    const uint32_t c1 = (r1 & 0x0ffffffc);
    const uint32_t c2 = (r2 & 0x0ffffffc);
    const uint32_t c3 = (r3 & 0x0ffffffc);
    // Repack into 5 26-bit limbs.
    st.r[0] =  c0                       & 0x3ffffff;
    st.r[1] = ((c0 >> 26) | (c1 <<  6)) & 0x3ffffff;
    st.r[2] = ((c1 >> 20) | (c2 << 12)) & 0x3ffffff;
    st.r[3] = ((c2 >> 14) | (c3 << 18)) & 0x3ffffff;
    st.r[4] =  (c3 >> 8)                & 0x3ffffff;

    st.s[0] = load32_le(key + 16);
    st.s[1] = load32_le(key + 20);
    st.s[2] = load32_le(key + 24);
    st.s[3] = load32_le(key + 28);

    for (int i = 0; i < 5; ++i) st.h[i] = 0;
}

// Process exactly 16 bytes of input (or padded final block of 16 bytes).
// hibit is 1 << 24 for full blocks, 0 for the padded tail block.
void block(State& st, const uint8_t m[16], uint32_t hibit) noexcept {
    // Convert 16 input bytes to 5 26-bit limbs and add to accumulator.
    const uint32_t t0 = load32_le(m + 0);
    const uint32_t t1 = load32_le(m + 4);
    const uint32_t t2 = load32_le(m + 8);
    const uint32_t t3 = load32_le(m + 12);

    uint64_t h0 = (uint64_t)st.h[0] + ( t0                       & 0x3ffffff);
    uint64_t h1 = (uint64_t)st.h[1] + (((t0 >> 26) | (t1 <<  6)) & 0x3ffffff);
    uint64_t h2 = (uint64_t)st.h[2] + (((t1 >> 20) | (t2 << 12)) & 0x3ffffff);
    uint64_t h3 = (uint64_t)st.h[3] + (((t2 >> 14) | (t3 << 18)) & 0x3ffffff);
    uint64_t h4 = (uint64_t)st.h[4] + ( (t3 >>  8)               | hibit);

    // h *= r mod (2^130 - 5). Use 5x5 schoolbook with 64-bit products.
    const uint64_t r0 = st.r[0];
    const uint64_t r1 = st.r[1];
    const uint64_t r2 = st.r[2];
    const uint64_t r3 = st.r[3];
    const uint64_t r4 = st.r[4];
    // s = 5 * r (used for reduction).
    const uint64_t s1 = r1 * 5;
    const uint64_t s2 = r2 * 5;
    const uint64_t s3 = r3 * 5;
    const uint64_t s4 = r4 * 5;

    uint64_t d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
    uint64_t d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2;
    uint64_t d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3;
    uint64_t d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4;
    uint64_t d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;

    // Carry/reduce.
    uint64_t c;
    c = d0 >> 26; d0 &= 0x3ffffff; d1 += c;
    c = d1 >> 26; d1 &= 0x3ffffff; d2 += c;
    c = d2 >> 26; d2 &= 0x3ffffff; d3 += c;
    c = d3 >> 26; d3 &= 0x3ffffff; d4 += c;
    c = d4 >> 26; d4 &= 0x3ffffff; d0 += c * 5;
    c = d0 >> 26; d0 &= 0x3ffffff; d1 += c;

    st.h[0] = (uint32_t)d0;
    st.h[1] = (uint32_t)d1;
    st.h[2] = (uint32_t)d2;
    st.h[3] = (uint32_t)d3;
    st.h[4] = (uint32_t)d4;
}

// Final tag = (h + s) mod 2^128 (after final reduction mod 2^130 - 5).
void finalize(State& st, uint8_t tag[16]) noexcept {
    // Fully reduce h mod 2^130 - 5.
    uint32_t h0 = st.h[0];
    uint32_t h1 = st.h[1];
    uint32_t h2 = st.h[2];
    uint32_t h3 = st.h[3];
    uint32_t h4 = st.h[4];

    // Carry chain to ensure each limb < 2^26.
    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    // Compute h + (-p) and conditionally subtract.
    uint32_t g0 = h0 + 5;
    c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1u << 26);

    // Mask: 0xffffffff if h >= p, else 0.
    const uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    const uint32_t nm = ~mask;
    h0 = (h0 & nm) | g0;
    h1 = (h1 & nm) | g1;
    h2 = (h2 & nm) | g2;
    h3 = (h3 & nm) | g3;
    h4 = (h4 & nm) | g4;

    // Re-pack to 4 32-bit words.
    const uint32_t f0 =  h0        | (h1 << 26);
    const uint32_t f1 = (h1 >>  6) | (h2 << 20);
    const uint32_t f2 = (h2 >> 12) | (h3 << 14);
    const uint32_t f3 = (h3 >> 18) | (h4 <<  8);

    // tag = (f + s) mod 2^128.
    uint64_t t = (uint64_t)f0 + st.s[0];
    store32_le(tag + 0, (uint32_t)t);
    t = (t >> 32) + (uint64_t)f1 + st.s[1];
    store32_le(tag + 4, (uint32_t)t);
    t = (t >> 32) + (uint64_t)f2 + st.s[2];
    store32_le(tag + 8, (uint32_t)t);
    t = (t >> 32) + (uint64_t)f3 + st.s[3];
    store32_le(tag + 12, (uint32_t)t);
}

void mac(const uint8_t key[32], const uint8_t* msg, size_t msg_len,
         uint8_t tag[16]) noexcept {
    State st;
    init(st, key);

    while (msg_len >= 16) {
        block(st, msg, 1u << 24);
        msg += 16;
        msg_len -= 16;
    }
    if (msg_len > 0) {
        // Pad final block: copy remaining bytes, append 0x01, zero the rest.
        uint8_t buf[16] = {0};
        for (size_t i = 0; i < msg_len; ++i) buf[i] = msg[i];
        buf[msg_len] = 1;
        block(st, buf, 0);
    }
    finalize(st, tag);
}

}  // namespace poly1305

// ===========================================================================
// ChaCha20-Poly1305 AEAD (RFC 8439 §2.8)
// ===========================================================================
namespace chacha20_poly1305 {

namespace {

// poly1305_key_gen (RFC 8439 §2.6): keystream block 0 with the given key/nonce
// produces a 64-byte block; we use the first 32 bytes as a one-time Poly1305
// key.
void derive_poly_key(const uint8_t key[32], const uint8_t nonce[12],
                     uint8_t poly_key[32]) noexcept {
    uint8_t ks[64];
    chacha20::block(key, nonce, 0, ks);
    for (int i = 0; i < 32; ++i) poly_key[i] = ks[i];
}

// Compute the AEAD MAC input per RFC 8439 §2.8:
//   aad || pad16(aad) || ciphertext || pad16(ciphertext) || len(aad) || len(ct)
// where pad16(x) zero-pads x up to a 16-byte boundary, and lengths are
// 8-byte little-endian.
//
// RFC 8439 §2.8 absorbs aad and ct as separate streams with explicit zero
// padding to 16-byte multiples — NOT with the 0x01 termination marker that
// the standalone Poly1305 mac() function adds. So we cannot reuse mac();
// we feed each partial block as a full 16-byte block with the 2^128 hibit.
void aead_mac(const uint8_t poly_key[32],
              const uint8_t* aad, size_t aad_len,
              const uint8_t* ct,  size_t ct_len,
              uint8_t tag[16]) noexcept {
    poly1305::State st;
    poly1305::init(st, poly_key);

    auto absorb_padded = [&](const uint8_t* p, size_t n) {
        while (n >= 16) {
            poly1305::block(st, p, 1u << 24);
            p += 16; n -= 16;
        }
        if (n > 0) {
            uint8_t buf[16] = {0};
            for (size_t i = 0; i < n; ++i) buf[i] = p[i];
            poly1305::block(st, buf, 1u << 24);
        }
    };

    absorb_padded(aad, aad_len);
    absorb_padded(ct, ct_len);

    // Length suffix: 8-byte LE aad_len || 8-byte LE ct_len. Always exactly
    // one 16-byte block, absorbed with the 2^128 hibit.
    uint8_t lens[16];
    store64_le(lens + 0, (uint64_t)aad_len);
    store64_le(lens + 8, (uint64_t)ct_len);
    poly1305::block(st, lens, 1u << 24);

    poly1305::finalize(st, tag);
}

// Constant-time 16-byte equality. Returns 1 on match, 0 otherwise.
inline uint8_t ct_eq16(const uint8_t a[16], const uint8_t b[16]) noexcept {
    uint8_t d = 0;
    for (int i = 0; i < 16; ++i) d |= (uint8_t)(a[i] ^ b[i]);
    // Reduce d to 0 (match) or 1 (mismatch), then invert to return 1 on match.
    return (uint8_t)(((uint32_t)d - 1u) >> 31);
}

}  // namespace

bool encrypt(const uint8_t key[32], const uint8_t nonce[12],
             const uint8_t* aad, size_t aad_len,
             const uint8_t* plaintext, size_t plaintext_len,
             uint8_t* ciphertext, uint8_t tag[16]) noexcept {
    if (key == nullptr || nonce == nullptr || tag == nullptr) return false;
    if (plaintext_len > 0 && (plaintext == nullptr || ciphertext == nullptr)) return false;
    if (aad_len > 0 && aad == nullptr) return false;

    uint8_t poly_key[32];
    derive_poly_key(key, nonce, poly_key);

    // Encrypt plaintext starting at counter = 1 (RFC 8439 §2.8).
    chacha20::xor_stream(key, nonce, 1, plaintext, plaintext_len, ciphertext);

    // MAC over (aad || pad || ct || pad || lens).
    aead_mac(poly_key, aad, aad_len, ciphertext, plaintext_len, tag);
    return true;
}

bool decrypt(const uint8_t key[32], const uint8_t nonce[12],
             const uint8_t* aad, size_t aad_len,
             const uint8_t* ciphertext, size_t ciphertext_len,
             const uint8_t tag[16], uint8_t* plaintext) noexcept {
    if (key == nullptr || nonce == nullptr || tag == nullptr) return false;
    if (ciphertext_len > 0 && (ciphertext == nullptr || plaintext == nullptr)) return false;
    if (aad_len > 0 && aad == nullptr) return false;

    uint8_t poly_key[32];
    derive_poly_key(key, nonce, poly_key);

    // Compute expected MAC over (aad || pad || ct || pad || lens).
    uint8_t expected[16];
    aead_mac(poly_key, aad, aad_len, ciphertext, ciphertext_len, expected);

    // Constant-time tag compare.
    if (ct_eq16(expected, tag) == 0) {
        return false;
    }

    // Decrypt only on tag verify success.
    chacha20::xor_stream(key, nonce, 1, ciphertext, ciphertext_len, plaintext);
    return true;
}

}  // namespace chacha20_poly1305

// ===========================================================================
// AES-256 (FIPS 197)
// ===========================================================================
//
// Constant-time, table-free S-box. The naive 256-byte LUT leaks via L1
// cache timing on shared cores (CACHEBLEED-class). We implement the S-box
// as bitsliced GF(2^8) arithmetic so every byte takes the same number of
// cycles regardless of value.
//
// MixColumns is implemented with the standard `xtime` doubling primitive
// (FIPS 197 §4.2.1) -- branchless `((x << 1) ^ ((x >> 7) * 0x1b)) & 0xff`.
// ===========================================================================
namespace aes {

namespace {

// Constant-time AES S-box via the Boyar-Peralta circuit (J. Cryptol. 2010,
// "A small depth-16 circuit for the AES S-Box"). 113 ops total, no table
// lookups, no data-dependent branches. This matches NIST FIPS 197 §5.1.1
// SubBytes byte-for-byte.
inline uint8_t aes_sbox(uint8_t x) noexcept {
    // Bit-level decomposition (LSB at index 0).
    uint8_t U0 = (x >> 7) & 1;
    uint8_t U1 = (x >> 6) & 1;
    uint8_t U2 = (x >> 5) & 1;
    uint8_t U3 = (x >> 4) & 1;
    uint8_t U4 = (x >> 3) & 1;
    uint8_t U5 = (x >> 2) & 1;
    uint8_t U6 = (x >> 1) & 1;
    uint8_t U7 =  x       & 1;

    // Top linear (compute the basis transforming GF(2^8) to the chosen
    // tower-field representation).
    uint8_t T1  = U0 ^ U3;
    uint8_t T2  = U0 ^ U5;
    uint8_t T3  = U0 ^ U6;
    uint8_t T4  = U3 ^ U5;
    uint8_t T5  = U4 ^ U6;
    uint8_t T6  = T1 ^ T5;
    uint8_t T7  = U1 ^ U2;
    uint8_t T8  = U7 ^ T6;
    uint8_t T9  = U7 ^ T7;
    uint8_t T10 = T6 ^ T7;
    uint8_t T11 = U1 ^ U5;
    uint8_t T12 = U2 ^ U5;
    uint8_t T13 = T3 ^ T4;
    uint8_t T14 = T6 ^ T11;
    uint8_t T15 = T5 ^ T11;
    uint8_t T16 = T5 ^ T12;
    uint8_t T17 = T9 ^ T16;
    uint8_t T18 = U3 ^ U7;
    uint8_t T19 = T7 ^ T18;
    uint8_t T20 = T1 ^ T19;
    uint8_t T21 = U6 ^ U7;
    uint8_t T22 = T7 ^ T21;
    uint8_t T23 = T2 ^ T22;
    uint8_t T24 = T2 ^ T10;
    uint8_t T25 = T20 ^ T17;
    uint8_t T26 = T3 ^ T16;
    uint8_t T27 = T1 ^ T12;

    // Inner non-linear core (the 4-bit inverse circuit).
    uint8_t M1  = T13 & T6;
    uint8_t M2  = T23 & T8;
    uint8_t M3  = T14 ^ M1;
    uint8_t M4  = T19 & U7;
    uint8_t M5  = M4 ^ M1;
    uint8_t M6  = T3 & T16;
    uint8_t M7  = T22 & T9;
    uint8_t M8  = T26 ^ M6;
    uint8_t M9  = T20 & T17;
    uint8_t M10 = M9 ^ M6;
    uint8_t M11 = T1 & T15;
    uint8_t M12 = T4 & T27;
    uint8_t M13 = M12 ^ M11;
    uint8_t M14 = T2 & T10;
    uint8_t M15 = M14 ^ M11;
    uint8_t M16 = M3 ^ M2;
    uint8_t M17 = M5 ^ T24;
    uint8_t M18 = M8 ^ M7;
    uint8_t M19 = M10 ^ M15;
    uint8_t M20 = M16 ^ M13;
    uint8_t M21 = M17 ^ M15;
    uint8_t M22 = M18 ^ M13;
    uint8_t M23 = M19 ^ T25;
    uint8_t M24 = M22 ^ M23;
    uint8_t M25 = M22 & M20;
    uint8_t M26 = M21 ^ M25;
    uint8_t M27 = M20 ^ M21;
    uint8_t M28 = M23 ^ M25;
    uint8_t M29 = M28 & M27;
    uint8_t M30 = M26 & M24;
    uint8_t M31 = M20 & M23;
    uint8_t M32 = M27 & M31;
    uint8_t M33 = M27 ^ M25;
    uint8_t M34 = M21 & M22;
    uint8_t M35 = M24 & M34;
    uint8_t M36 = M24 ^ M25;
    uint8_t M37 = M21 ^ M29;
    uint8_t M38 = M32 ^ M33;
    uint8_t M39 = M23 ^ M30;
    uint8_t M40 = M35 ^ M36;
    uint8_t M41 = M38 ^ M40;
    uint8_t M42 = M37 ^ M39;
    uint8_t M43 = M37 ^ M38;
    uint8_t M44 = M39 ^ M40;
    uint8_t M45 = M42 ^ M41;
    uint8_t M46 = M44 & T6;
    uint8_t M47 = M40 & T8;
    uint8_t M48 = M39 & U7;
    uint8_t M49 = M43 & T16;
    uint8_t M50 = M38 & T9;
    uint8_t M51 = M37 & T17;
    uint8_t M52 = M42 & T15;
    uint8_t M53 = M45 & T27;
    uint8_t M54 = M41 & T10;
    uint8_t M55 = M44 & T13;
    uint8_t M56 = M40 & T23;
    uint8_t M57 = M39 & T19;
    uint8_t M58 = M43 & T3;
    uint8_t M59 = M38 & T22;
    uint8_t M60 = M37 & T20;
    uint8_t M61 = M42 & T1;
    uint8_t M62 = M45 & T4;
    uint8_t M63 = M41 & T2;

    // Bottom linear (transforms back to GF(2^8) and applies the affine
    // transform that distinguishes SubBytes from pure inversion).
    uint8_t L0  = M61 ^ M62;
    uint8_t L1  = M50 ^ M56;
    uint8_t L2  = M46 ^ M48;
    uint8_t L3  = M47 ^ M55;
    uint8_t L4  = M54 ^ M58;
    uint8_t L5  = M49 ^ M61;
    uint8_t L6  = M62 ^ L5;
    uint8_t L7  = M46 ^ L3;
    uint8_t L8  = M51 ^ M59;
    uint8_t L9  = M52 ^ M53;
    uint8_t L10 = M53 ^ L4;
    uint8_t L11 = M60 ^ L2;
    uint8_t L12 = M48 ^ M51;
    uint8_t L13 = M50 ^ L0;
    uint8_t L14 = M52 ^ M61;
    uint8_t L15 = M55 ^ L1;
    uint8_t L16 = M56 ^ L0;
    uint8_t L17 = M57 ^ L1;
    uint8_t L18 = M58 ^ L8;
    uint8_t L19 = M63 ^ L4;
    uint8_t L20 = L0 ^ L1;
    uint8_t L21 = L1 ^ L7;
    uint8_t L22 = L3 ^ L12;
    uint8_t L23 = L18 ^ L2;
    uint8_t L24 = L15 ^ L9;
    uint8_t L25 = L6 ^ L10;
    uint8_t L26 = L7 ^ L9;
    uint8_t L27 = L8 ^ L10;
    uint8_t L28 = L11 ^ L14;
    uint8_t L29 = L11 ^ L17;

    uint8_t S0 = L6  ^ L24;
    uint8_t S1 = L16 ^ L26;     S1 ^= 1;  // affine constant
    uint8_t S2 = L19 ^ L28;     S2 ^= 1;
    uint8_t S3 = L6  ^ L21;
    uint8_t S4 = L20 ^ L22;
    uint8_t S5 = L25 ^ L29;
    uint8_t S6 = L13 ^ L27;     S6 ^= 1;
    uint8_t S7 = L6  ^ L23;     S7 ^= 1;

    return (uint8_t)(
        ((S0 & 1) << 7) |
        ((S1 & 1) << 6) |
        ((S2 & 1) << 5) |
        ((S3 & 1) << 4) |
        ((S4 & 1) << 3) |
        ((S5 & 1) << 2) |
        ((S6 & 1) << 1) |
        ( S7 & 1));
}

// AES Rcon (FIPS 197 §5.2). Only 7 values are needed for AES-256
// (round-constants for keys 1..7 cover all 60 expanded words).
constexpr uint8_t RCON[7] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40 };

inline uint8_t xtime(uint8_t x) noexcept {
    // Multiply by 2 in GF(2^8) with reduction polynomial 0x11b.
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

}  // namespace

void expand_key_256(const uint8_t key[32], uint8_t rk[AES256_KS_BYTES]) noexcept {
    // First 32 bytes are the raw key.
    for (int i = 0; i < 32; ++i) rk[i] = key[i];

    // Generate words 8..59 (each word is 4 bytes).
    for (int i = 8; i < AES256_KS_WORDS; ++i) {
        uint8_t t0 = rk[(i - 1) * 4 + 0];
        uint8_t t1 = rk[(i - 1) * 4 + 1];
        uint8_t t2 = rk[(i - 1) * 4 + 2];
        uint8_t t3 = rk[(i - 1) * 4 + 3];

        if ((i & 7) == 0) {
            // RotWord then SubWord then XOR Rcon.
            const uint8_t r0 = t1, r1 = t2, r2 = t3, r3 = t0;
            t0 = (uint8_t)(aes_sbox(r0) ^ RCON[(i / 8) - 1]);
            t1 = aes_sbox(r1);
            t2 = aes_sbox(r2);
            t3 = aes_sbox(r3);
        } else if ((i & 7) == 4) {
            // SubWord only (the AES-256 extra step).
            t0 = aes_sbox(t0);
            t1 = aes_sbox(t1);
            t2 = aes_sbox(t2);
            t3 = aes_sbox(t3);
        }

        rk[i * 4 + 0] = (uint8_t)(rk[(i - 8) * 4 + 0] ^ t0);
        rk[i * 4 + 1] = (uint8_t)(rk[(i - 8) * 4 + 1] ^ t1);
        rk[i * 4 + 2] = (uint8_t)(rk[(i - 8) * 4 + 2] ^ t2);
        rk[i * 4 + 3] = (uint8_t)(rk[(i - 8) * 4 + 3] ^ t3);
    }
}

void encrypt_block(const uint8_t rk[AES256_KS_BYTES],
                   const uint8_t in[16], uint8_t out[16]) noexcept {
    // State is a 4x4 column-major byte matrix per FIPS 197 §3.4.
    uint8_t s[16];
    for (int i = 0; i < 16; ++i) s[i] = (uint8_t)(in[i] ^ rk[i]);

    for (int round = 1; round < AES256_ROUNDS; ++round) {
        // SubBytes.
        for (int i = 0; i < 16; ++i) s[i] = aes_sbox(s[i]);

        // ShiftRows (state layout is column-major: s[c*4 + r]).
        // Row r is left-rotated by r positions (FIPS 197 §5.1.2).
        uint8_t t;
        // Row 1 (indices 1, 5, 9, 13): rotate by 1.
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        // Row 2 (indices 2, 6, 10, 14): rotate by 2.
        t = s[2];  s[2]  = s[10]; s[10] = t;
        t = s[6];  s[6]  = s[14]; s[14] = t;
        // Row 3 (indices 3, 7, 11, 15): rotate by 3 == rotate right by 1.
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;

        // MixColumns (FIPS 197 §5.1.3): per column, treat as poly mult by
        // {03}x^3 + {01}x^2 + {01}x + {02} mod x^4 + 1.
        for (int c = 0; c < 4; ++c) {
            uint8_t a0 = s[c*4 + 0];
            uint8_t a1 = s[c*4 + 1];
            uint8_t a2 = s[c*4 + 2];
            uint8_t a3 = s[c*4 + 3];
            uint8_t x  = a0 ^ a1 ^ a2 ^ a3;  // x = sum.
            uint8_t y0 = a0;
            s[c*4 + 0] = (uint8_t)(a0 ^ x ^ xtime(a0 ^ a1));
            s[c*4 + 1] = (uint8_t)(a1 ^ x ^ xtime(a1 ^ a2));
            s[c*4 + 2] = (uint8_t)(a2 ^ x ^ xtime(a2 ^ a3));
            s[c*4 + 3] = (uint8_t)(a3 ^ x ^ xtime(a3 ^ y0));
        }

        // AddRoundKey.
        for (int i = 0; i < 16; ++i) s[i] ^= rk[round * 16 + i];
    }

    // Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns).
    for (int i = 0; i < 16; ++i) s[i] = aes_sbox(s[i]);
    {
        uint8_t t;
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        t = s[2];  s[2]  = s[10]; s[10] = t;
        t = s[6];  s[6]  = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
    }
    for (int i = 0; i < 16; ++i) {
        out[i] = (uint8_t)(s[i] ^ rk[AES256_ROUNDS * 16 + i]);
    }
}

}  // namespace aes

// ===========================================================================
// AES-256-GCM (NIST SP 800-38D)
// ===========================================================================
namespace aes_256_gcm {

namespace {

// Big-endian 32-bit and 64-bit helpers. GCM is BE throughout.
inline uint32_t load32_be(const uint8_t* p) noexcept {
    return  ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         |  ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}
inline void store32_be(uint8_t* p, uint32_t v) noexcept {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)(v);
}
inline void store64_be(uint8_t* p, uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * (7 - i)));
}

// GHASH multiplication in GF(2^128) with reduction polynomial
// x^128 + x^7 + x^2 + x + 1 (NIST SP 800-38D §6.3). Bits are numbered
// "GCM-style": bit 0 is the most significant bit of byte 0.
//
// Constant-time: 128 iterations regardless of input bits.
void ghash_mul(uint8_t z[16], const uint8_t h[16]) noexcept {
    uint8_t v[16];
    for (int i = 0; i < 16; ++i) v[i] = h[i];
    uint8_t r[16] = {0};

    for (int i = 0; i < 128; ++i) {
        // Test bit i of z (GCM bit ordering: byte i/8, MSB-first within byte).
        const uint8_t zbit = (uint8_t)((z[i >> 3] >> (7 - (i & 7))) & 1);
        // mask = 0xff if zbit is 1, else 0.
        const uint8_t mask = (uint8_t)(0u - zbit);
        for (int j = 0; j < 16; ++j) r[j] ^= (uint8_t)(v[j] & mask);

        // Shift v right by one bit; if low bit was set, XOR reduction R.
        const uint8_t lsb = (uint8_t)(v[15] & 1);
        for (int j = 15; j > 0; --j) {
            v[j] = (uint8_t)((v[j] >> 1) | ((v[j-1] & 1) << 7));
        }
        v[0] >>= 1;
        // R = e1 || 0^120 (i.e. byte 0 = 0xe1, all others 0).
        const uint8_t rmask = (uint8_t)(0u - lsb);
        v[0] ^= (uint8_t)(0xe1u & rmask);
    }

    for (int i = 0; i < 16; ++i) z[i] = r[i];
}

// inc32 on the rightmost 32 bits of a 16-byte counter (SP 800-38D §6.2).
inline void inc32(uint8_t ctr[16]) noexcept {
    uint32_t c = load32_be(ctr + 12);
    c += 1;  // 32-bit wraparound is the spec.
    store32_be(ctr + 12, c);
}

// Absorb a buffer into GHASH, padding final partial block with zeros.
void ghash_update(uint8_t y[16], const uint8_t h[16],
                  const uint8_t* data, size_t len) noexcept {
    while (len >= 16) {
        for (int i = 0; i < 16; ++i) y[i] ^= data[i];
        ghash_mul(y, h);
        data += 16; len -= 16;
    }
    if (len > 0) {
        uint8_t buf[16] = {0};
        for (size_t i = 0; i < len; ++i) buf[i] = data[i];
        for (int i = 0; i < 16; ++i) y[i] ^= buf[i];
        ghash_mul(y, h);
    }
}

// GCTR (SP 800-38D §6.5): XOR `data` with the AES-CTR keystream starting
// at `ctr`, writing to `out`. Increments `ctr` per 16-byte block.
void gctr(const uint8_t rk[aes::AES256_KS_BYTES], uint8_t ctr[16],
          const uint8_t* data, size_t len, uint8_t* out) noexcept {
    uint8_t ks[16];
    while (len >= 16) {
        aes::encrypt_block(rk, ctr, ks);
        for (int i = 0; i < 16; ++i) out[i] = (uint8_t)(data[i] ^ ks[i]);
        inc32(ctr);
        data += 16; out += 16; len -= 16;
    }
    if (len > 0) {
        aes::encrypt_block(rk, ctr, ks);
        for (size_t i = 0; i < len; ++i) out[i] = (uint8_t)(data[i] ^ ks[i]);
        inc32(ctr);
    }
}

// Constant-time 16-byte equality. Returns 1 on match, 0 otherwise.
inline uint8_t ct_eq16(const uint8_t a[16], const uint8_t b[16]) noexcept {
    uint8_t d = 0;
    for (int i = 0; i < 16; ++i) d |= (uint8_t)(a[i] ^ b[i]);
    return (uint8_t)(((uint32_t)d - 1u) >> 31);
}

}  // namespace

bool encrypt(const uint8_t key[32], const uint8_t iv[12],
             const uint8_t* aad, size_t aad_len,
             const uint8_t* plaintext, size_t plaintext_len,
             uint8_t* ciphertext, uint8_t tag[16]) noexcept {
    if (key == nullptr || iv == nullptr || tag == nullptr) return false;
    if (plaintext_len > 0 && (plaintext == nullptr || ciphertext == nullptr)) return false;
    if (aad_len > 0 && aad == nullptr) return false;

    uint8_t rk[aes::AES256_KS_BYTES];
    aes::expand_key_256(key, rk);

    // H = AES_K(0^128).
    uint8_t H[16];
    {
        uint8_t zero[16] = {0};
        aes::encrypt_block(rk, zero, H);
    }

    // J0 = IV || 0x00000001 (96-bit IV path, SP 800-38D §7.1 step 2).
    uint8_t J0[16];
    for (int i = 0; i < 12; ++i) J0[i] = iv[i];
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    // Encrypt plaintext under counter starting at inc32(J0).
    uint8_t ctr[16];
    for (int i = 0; i < 16; ++i) ctr[i] = J0[i];
    inc32(ctr);
    gctr(rk, ctr, plaintext, plaintext_len, ciphertext);

    // GHASH = AAD || pad || CT || pad || len64(AAD) || len64(CT)  -- in BITS.
    uint8_t Y[16] = {0};
    ghash_update(Y, H, aad, aad_len);
    ghash_update(Y, H, ciphertext, plaintext_len);
    {
        uint8_t lens[16];
        store64_be(lens + 0, (uint64_t)aad_len * 8u);
        store64_be(lens + 8, (uint64_t)plaintext_len * 8u);
        for (int i = 0; i < 16; ++i) Y[i] ^= lens[i];
        ghash_mul(Y, H);
    }

    // Tag = GHASH XOR AES_K(J0).
    uint8_t s[16];
    aes::encrypt_block(rk, J0, s);
    for (int i = 0; i < 16; ++i) tag[i] = (uint8_t)(Y[i] ^ s[i]);
    return true;
}

bool decrypt(const uint8_t key[32], const uint8_t iv[12],
             const uint8_t* aad, size_t aad_len,
             const uint8_t* ciphertext, size_t ciphertext_len,
             const uint8_t tag[16], uint8_t* plaintext) noexcept {
    if (key == nullptr || iv == nullptr || tag == nullptr) return false;
    if (ciphertext_len > 0 && (ciphertext == nullptr || plaintext == nullptr)) return false;
    if (aad_len > 0 && aad == nullptr) return false;

    uint8_t rk[aes::AES256_KS_BYTES];
    aes::expand_key_256(key, rk);

    // H = AES_K(0^128); J0 as above.
    uint8_t H[16];
    {
        uint8_t zero[16] = {0};
        aes::encrypt_block(rk, zero, H);
    }
    uint8_t J0[16];
    for (int i = 0; i < 12; ++i) J0[i] = iv[i];
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    // Compute expected tag over (aad, ciphertext, len64s).
    uint8_t Y[16] = {0};
    ghash_update(Y, H, aad, aad_len);
    ghash_update(Y, H, ciphertext, ciphertext_len);
    {
        uint8_t lens[16];
        store64_be(lens + 0, (uint64_t)aad_len * 8u);
        store64_be(lens + 8, (uint64_t)ciphertext_len * 8u);
        for (int i = 0; i < 16; ++i) Y[i] ^= lens[i];
        ghash_mul(Y, H);
    }
    uint8_t s[16];
    aes::encrypt_block(rk, J0, s);
    uint8_t expected[16];
    for (int i = 0; i < 16; ++i) expected[i] = (uint8_t)(Y[i] ^ s[i]);

    // Constant-time tag compare. Refuse to write plaintext on mismatch.
    if (ct_eq16(expected, tag) == 0) {
        return false;
    }

    // Decrypt under counter starting at inc32(J0).
    uint8_t ctr[16];
    for (int i = 0; i < 16; ++i) ctr[i] = J0[i];
    inc32(ctr);
    gctr(rk, ctr, ciphertext, ciphertext_len, plaintext);
    return true;
}

}  // namespace aes_256_gcm

}  // namespace kinet::crypto::aead

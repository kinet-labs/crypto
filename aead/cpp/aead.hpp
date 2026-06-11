// First-party AEAD primitives. Two ciphers, one canonical surface:
//
//   * ChaCha20-Poly1305 (RFC 8439)        -- 256-bit key, 96-bit nonce.
//   * AES-256-GCM       (NIST SP 800-38D) -- 256-bit key, 96-bit IV (the
//                                            FIPS-recommended length, and
//                                            the only length we support --
//                                            arbitrary IV lengths require
//                                            a separate GHASH derivation
//                                            that no real consumer needs).
//
// Both ciphers expose the same {seal, open} contract; `open` performs a
// constant-time tag compare and refuses to write plaintext on tag mismatch.
//
// Pieces, intentionally orthogonal for auditability:
//   * chacha20::block       -- one 64-byte ChaCha20 keystream block.
//   * chacha20::xor_stream  -- ChaCha20 counter-mode XOR (initial counter = 1).
//   * poly1305::mac         -- one-time MAC over a byte buffer.
//   * chacha20_poly1305::*  -- AEAD construction (RFC 8439 §2.8).
//   * aes::expand_key_256   -- AES-256 key schedule (FIPS 197).
//   * aes::encrypt_block    -- one 16-byte AES-256 ECB block (FIPS 197).
//   * aes_256_gcm::*        -- AEAD construction (NIST SP 800-38D, 96-bit IV).
//
// No external dependencies. Pure portable C++.
//
// References:
//   - RFC 8439                      (ChaCha20-Poly1305 spec, ground truth).
//   - D.J. Bernstein, ChaCha20 (2008), Poly1305-AES (2005). Public domain.
//   - FIPS PUB 197 (Nov 2001)       (AES specification).
//   - NIST SP 800-38D (Nov 2007)    (Galois/Counter Mode of Operation).

#pragma once

#include <cstddef>
#include <cstdint>

namespace kinet::crypto::aead {

// ---------------------------------------------------------------------------
// ChaCha20 (RFC 8439 §2.3)
// ---------------------------------------------------------------------------
namespace chacha20 {

// Generate one 64-byte keystream block.
//   key    -- 32-byte symmetric key.
//   nonce  -- 12-byte nonce (IETF variant).
//   counter-- 32-bit block counter.
//   out    -- 64-byte output buffer.
void block(const uint8_t key[32], const uint8_t nonce[12],
           uint32_t counter, uint8_t out[64]) noexcept;

// XOR a buffer with the ChaCha20 keystream starting at the given counter.
// Buffer is encrypted in place if in == out.
void xor_stream(const uint8_t key[32], const uint8_t nonce[12],
                uint32_t counter, const uint8_t* in, size_t len,
                uint8_t* out) noexcept;

}  // namespace chacha20

// ---------------------------------------------------------------------------
// Poly1305 (RFC 8439 §2.5)
// ---------------------------------------------------------------------------
namespace poly1305 {

// Internal state. Exposed for the AEAD layer (which absorbs aad/ciphertext
// in distinct phases with explicit zero-padding); standalone callers should
// prefer mac().
struct State {
    uint32_t r[5];
    uint32_t s[4];
    uint32_t h[5];
};

// Initialize state from a 32-byte one-time key.
void init(State& st, const uint8_t key[32]) noexcept;

// Absorb one 16-byte block. hibit = (1 << 24) for full message blocks
// per RFC 8439; the AEAD construction also uses (1 << 24) for partial
// final blocks of aad/ct after zero-padding to 16 bytes.
void block(State& st, const uint8_t m[16], uint32_t hibit) noexcept;

// Produce the final 16-byte tag. Consumes state.
void finalize(State& st, uint8_t tag[16]) noexcept;

// Convenience: compute Poly1305 MAC over an arbitrary buffer using the
// standalone framing (final partial block padded with 0x01 marker per
// RFC 8439 §2.5 standalone semantics).
//   key    -- 32-byte one-time key (must be unique per message).
//   msg    -- arbitrary-length message.
//   tag    -- 16-byte authentication tag output.
void mac(const uint8_t key[32], const uint8_t* msg, size_t msg_len,
         uint8_t tag[16]) noexcept;

}  // namespace poly1305

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 AEAD (RFC 8439 §2.8)
// ---------------------------------------------------------------------------
namespace chacha20_poly1305 {

// Encrypt + authenticate. Returns true on success.
//   key            -- 32-byte symmetric key.
//   nonce          -- 12-byte nonce (must be unique per (key, message)).
//   aad            -- additional authenticated data (may be null if aad_len = 0).
//   plaintext      -- input plaintext (may be null if plaintext_len = 0).
//   ciphertext     -- output buffer of plaintext_len bytes.
//   tag            -- 16-byte authentication tag output.
bool encrypt(const uint8_t key[32], const uint8_t nonce[12],
             const uint8_t* aad, size_t aad_len,
             const uint8_t* plaintext, size_t plaintext_len,
             uint8_t* ciphertext, uint8_t tag[16]) noexcept;

// Verify + decrypt. Returns true if the tag is valid (constant-time compare),
// false otherwise. On false, plaintext contents are undefined.
bool decrypt(const uint8_t key[32], const uint8_t nonce[12],
             const uint8_t* aad, size_t aad_len,
             const uint8_t* ciphertext, size_t ciphertext_len,
             const uint8_t tag[16], uint8_t* plaintext) noexcept;

}  // namespace chacha20_poly1305

// ---------------------------------------------------------------------------
// AES-256 (FIPS 197)
// ---------------------------------------------------------------------------
namespace aes {

// AES-256 has 14 rounds; the expanded key holds 15 round keys (the initial
// XOR + one per round). Each round key is 16 bytes -> 240 bytes total.
constexpr int AES256_ROUNDS    = 14;
constexpr int AES256_KS_BYTES  = 240;
constexpr int AES256_KS_WORDS  = AES256_KS_BYTES / 4;  // 60 32-bit words.

// Expand a 32-byte AES-256 key into a 240-byte round-key schedule
// (FIPS 197 §5.2 KeyExpansion). Output is 60 little-endian-ish 32-bit
// words stored as bytes -- see encrypt_block for how they are consumed.
void expand_key_256(const uint8_t key[32], uint8_t round_keys[AES256_KS_BYTES]) noexcept;

// Encrypt one 16-byte block with the expanded round keys (FIPS 197 §5.1
// Cipher). Constant-time table-free S-box is used here -- safe to call on
// secret inputs without timing leakage from cache state.
void encrypt_block(const uint8_t round_keys[AES256_KS_BYTES],
                   const uint8_t in[16], uint8_t out[16]) noexcept;

}  // namespace aes

// ---------------------------------------------------------------------------
// AES-256-GCM (NIST SP 800-38D)
// ---------------------------------------------------------------------------
//
// Only the 96-bit IV branch is implemented. Per SP 800-38D §5.2.1.1, with
// |IV| = 96, J0 = IV || 0^31 || 1; the alternate hashed-IV branch is unused
// in modern protocols (TLS 1.2/1.3, IPsec, SSH, JOSE all standardize on 96).
//
namespace aes_256_gcm {

// Encrypt + authenticate. Returns true on success.
//   key            -- 32-byte symmetric key.
//   iv             -- 12-byte IV (must be unique per (key, message)).
//   aad            -- additional authenticated data (may be null if aad_len = 0).
//   plaintext      -- input plaintext (may be null if plaintext_len = 0).
//   ciphertext     -- output buffer of plaintext_len bytes.
//   tag            -- 16-byte authentication tag output.
bool encrypt(const uint8_t key[32], const uint8_t iv[12],
             const uint8_t* aad, size_t aad_len,
             const uint8_t* plaintext, size_t plaintext_len,
             uint8_t* ciphertext, uint8_t tag[16]) noexcept;

// Verify + decrypt. Returns true on tag verification success
// (constant-time compare). On failure, plaintext contents are undefined.
bool decrypt(const uint8_t key[32], const uint8_t iv[12],
             const uint8_t* aad, size_t aad_len,
             const uint8_t* ciphertext, size_t ciphertext_len,
             const uint8_t tag[16], uint8_t* plaintext) noexcept;

}  // namespace aes_256_gcm

}  // namespace kinet::crypto::aead

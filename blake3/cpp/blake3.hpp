// First-party BLAKE3 (https://github.com/BLAKE3-team/BLAKE3-spec).
//
// Implements the three official modes:
//   - hash:        plain hash, 32-byte output
//   - keyed_hash:  32-byte key, 32-byte output
//   - derive_key:  context string + key material, 32-byte output
//
// Plus XOF output of arbitrary length for any of the three modes.
//
// No third-party dependencies; constants and round structure straight from
// the spec.

#pragma once
#include <cstddef>
#include <cstdint>

namespace kinet::crypto::blake3 {

constexpr std::size_t HASH_LEN  = 32;
constexpr std::size_t KEY_LEN   = 32;
constexpr std::size_t BLOCK_LEN = 64;
constexpr std::size_t CHUNK_LEN = 1024;

/// Plain BLAKE3 hash. out_len bytes of XOF output written to out.
/// out_len = 32 yields the standard BLAKE3 digest.
void hash(const uint8_t* in, std::size_t in_len,
          uint8_t* out, std::size_t out_len) noexcept;

/// Convenience: 32-byte digest into a fixed-size buffer.
inline void hash32(const uint8_t* in, std::size_t in_len,
                   uint8_t out[HASH_LEN]) noexcept {
    hash(in, in_len, out, HASH_LEN);
}

/// Keyed-hash mode (MAC). Key is exactly 32 bytes.
void keyed_hash(const uint8_t key[KEY_LEN],
                const uint8_t* in, std::size_t in_len,
                uint8_t* out, std::size_t out_len) noexcept;

/// derive_key mode: derives a 32-byte key from a context string and key
/// material. context_str is a null-terminated context string (per spec it
/// should be a hardcoded ASCII constant, not user input).
void derive_key(const char* context_str, std::size_t context_str_len,
                const uint8_t* key_material, std::size_t key_material_len,
                uint8_t* out, std::size_t out_len) noexcept;

}  // namespace kinet::crypto::blake3

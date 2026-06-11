// Lamport one-time signatures (LP-2506) over SHA-256.
//
// Surface:
//   M = 256 (msg digest bits)
//   N =  32 (SHA-256 preimage size)
//   sk = M * 2 * N        bytes  (two preimages per bit)
//   pk = M * 2 * N        bytes  (sha256 of each preimage)
//   sig = M * N           bytes  (one preimage per bit, selected by msg)
//
// Deterministic key generation from a 32-byte seed:
//     sk[i*2 + b] = sha256(seed || u32_be(i*2 + b))    for i in [0,M), b in {0,1}
//
// Signing:
//     for each bit i of msg32 (MSB-first inside each byte):
//         sig[i] = sk[i*2 + bit_i]
//
// Verification:
//     for each bit i:
//         require sha256(sig[i]) == pk[i*2 + bit_i]

#pragma once

#include <cstddef>
#include <cstdint>

namespace kinet::crypto::lamport
{

inline constexpr std::size_t MSG_BITS    = 256;
inline constexpr std::size_t HASH_SIZE   = 32;
inline constexpr std::size_t SK_SIZE     = MSG_BITS * 2 * HASH_SIZE;  // 16384
inline constexpr std::size_t PK_SIZE     = MSG_BITS * 2 * HASH_SIZE;  // 16384
inline constexpr std::size_t SIG_SIZE    = MSG_BITS * HASH_SIZE;      //  8192

/// Derive (sk, pk) from `seed[32]`. Both buffers must be at least
/// SK_SIZE / PK_SIZE bytes long. Deterministic.
void keygen(const uint8_t seed[32], uint8_t* sk, uint8_t* pk) noexcept;

/// Sign a 32-byte message digest. `sig` must be at least SIG_SIZE bytes long.
/// `sk` must be the secret key emitted by keygen().
void sign(const uint8_t* sk, const uint8_t msg32[32], uint8_t* sig) noexcept;

/// Verify a signature. Returns true iff `sig` is valid for `msg32` under `pk`.
bool verify(const uint8_t* pk, const uint8_t msg32[32], const uint8_t* sig) noexcept;

/// Bit accessor used by sign/verify. Bit 0 is the most-significant bit of
/// msg32[0] (MSB-first scan). Exposed so the GPU drivers and tests can use the
/// exact same convention.
inline uint8_t msg_bit(const uint8_t msg32[32], std::size_t i) noexcept {
    return uint8_t((msg32[i >> 3] >> (7 - (i & 7))) & 1);
}

}  // namespace kinet::crypto::lamport

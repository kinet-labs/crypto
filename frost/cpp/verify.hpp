// FROST verify — standard Schnorr verification on the FROST(secp256k1, SHA-256)
// ciphersuite, encoded for the BIP-340-style 64-byte wire format used by the
// public C-ABI.
//
// Inputs:
//   pk[32]       : x-only public key (BIP-340 convention: lifted to even y)
//   msg, msg_len : message bytes  (FROST hashes the message directly; the
//                  caller is responsible for any domain separation)
//   sig[64]      : R_x[32] || z[32]
//
// Verification equation:
//   c = SHA256(R_x || pk_x || msg)             -- BIP-340-shaped challenge
//   z * G == R + c * pk                         -- where R, pk are lift_x'd
//
// Returns true iff the signature verifies.

#pragma once

#include <cstddef>
#include <cstdint>

namespace kinet::crypto::frost {

bool verify(const uint8_t pk[32],
            const uint8_t* msg,
            std::size_t    msg_len,
            const uint8_t  sig[64]) noexcept;

}  // namespace kinet::crypto::frost

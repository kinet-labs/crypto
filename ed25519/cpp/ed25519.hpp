// Ed25519 (EdDSA on Curve25519) host CPU API per RFC 8032.
//
// Backed by ed25519-donna (Andrew Moon, public-domain) vendored at
// cpp/ed25519-donna/. Self-contained: no OpenSSL, no CommonCrypto, no
// platform-specific assembly required (works on x86-64 and Apple Silicon).
//
// "Secret key" in this API is the NaCl-style 64-byte form
//   sk[ 0..32) = the 32-byte seed (RFC 8032 §5.1.5 "private key")
//   sk[32..64) = the corresponding 32-byte public key
// This matches the most common embedding (libsodium, Tendermint, Tor, GnuPG)
// and lets sign() avoid recomputing the public key.

#pragma once

#include <cstddef>
#include <cstdint>

namespace kinet::crypto::ed25519 {

// Derive a key pair from a 32-byte seed.
//   pk   - 32-byte public key (output)
//   sk   - 64-byte secret key (output): seed || pk
//   seed - 32-byte private seed (input)
void keygen(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]);

// Sign `msg` (msg_len bytes) under (pk, sk).
//   sig - 64-byte output (R || S, RFC 8032 §5.1.6)
//   pk  - 32-byte public key
//   sk  - 64-byte secret key (seed || pk); only sk[0..32) is used as the seed
void sign(uint8_t       sig[64],
          const uint8_t* msg, std::size_t msg_len,
          const uint8_t pk[32],
          const uint8_t sk[64]);

// Verify a single signature. Returns true iff the signature is valid.
// Constant-time with respect to (sig, pk); the caller's branch on the result
// is the only timing channel.
bool verify(const uint8_t* msg, std::size_t msg_len,
            const uint8_t sig[64],
            const uint8_t pk[32]);

// Verify a batch of `n` (msg, sig, pk) triples. Returns true iff all
// signatures verify. On failure, the caller cannot tell which signature
// failed without a fallback to single-verify (deliberate: the batched
// equation either holds or doesn't).
//
// Implementation is the Pornin-Bernstein batched verification using a
// random linear combination of the per-signature verification equations
// (ed25519-donna sign_open_batch). Provides ~2x speedup at n=8 and ~3.5x
// at n=64 on M1 Max.
//
// Pointers in `msgs`, `msg_lens`, `sigs`, `pks` must reference n entries
// each; individual byte buffers must remain live until the call returns.
bool batch_verify(std::size_t          n,
                  const uint8_t* const* msgs,
                  const std::size_t*    msg_lens,
                  const uint8_t* const* sigs,
                  const uint8_t* const* pks);

} // namespace kinet::crypto::ed25519

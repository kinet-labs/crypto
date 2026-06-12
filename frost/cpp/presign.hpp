// FROST batched pre-signing kernel — CPU canonical body.
//
// FROST (Flexible Round-Optimized Schnorr Threshold, RFC 9591) splits the
// signing protocol into two rounds. Round 1 is local crypto only: each signer
// generates a nonce pair (d_i, e_i) sampled uniformly from F_n, computes
// commitments D_i = d_i*G, E_i = e_i*G, and broadcasts the commitments.
//
// Round 1 is independent across (signer, batch slot). One kernel runs
// M signers × N batch slots in parallel and produces M*N commitment pairs.
//
// Determinism. For testing and post-hoc auditability we derive the nonce
// pair deterministically from a per-context seed:
//
//   nonce_seed = HKDF-Expand(
//       HKDF-Extract(salt = "frost-presign-v1", ikm = seed),
//       info = signer_id_le32 || slot_id_le32,
//       L = 64)
//   d_i = OS2IP(nonce_seed[ 0..32]) mod n   (reject 0)
//   e_i = OS2IP(nonce_seed[32..64]) mod n   (reject 0)
//
// In production the seed is sourced from a TEE-resident KMS root and the
// (signer, slot) tuple is the only public salt — this is what keeps each
// pre-signature unique.
//
// GPU residency. The host never sees (d_i, e_i). The CPU body keeps the nonce
// in an opaque buffer that lives only as long as the FROST context; GPU
// backends keep it in private/threadgroup memory and the host buffer at
// boundary crossing only carries the (D_i, E_i) commitment.
//
// Output layout. Per slot the kernel writes:
//
//   commitment[66] = D_i (33-byte compressed) || E_i (33-byte compressed)
//
// And keeps internally:
//
//   nonce[64]     = d_i (32-byte big-endian) || e_i (32-byte big-endian)
//
// Curve. secp256k1 (RFC 9591 §6.4 ciphersuite FROST(secp256k1, SHA-256)).

#pragma once

#include <cstddef>
#include <cstdint>

namespace kinet::crypto::frost {

// One slot of pre-signing output. Public commitments only.
struct CommitmentSlot {
    uint8_t D[33];   // d_i * G, compressed sec1
    uint8_t E[33];   // e_i * G, compressed sec1
};

// One slot of secret nonces. Caller must keep this in a buffer that the host
// process cannot leak (TEE, mlocked page, attested GPU memory). Lives until
// the matching online round consumes it.
struct NonceSlot {
    uint8_t d[32];   // d_i, big-endian
    uint8_t e[32];   // e_i, big-endian
};

// Compute one slot. signer_id and slot_id are 32-bit little-endian ints
// concatenated as info. seed is a per-context 32-byte secret.
//
// Returns 0 on success, -1 if signer_id == 0 (FROST forbids id 0).
int presign_one(const uint8_t seed[32],
                uint32_t signer_id,
                uint32_t slot_id,
                CommitmentSlot& commit_out,
                NonceSlot&      nonce_out) noexcept;

// Batched form: M signers × N slots, row-major (signer-major).
// commits_out and nonces_out must point at M*N entries each.
//
// Pure CPU body. Backends call into this through the C-ABI shim.
//
// Returns 0 on success, -1 on argument error (m == 0 or n == 0 or null
// pointer or signer id 0 in any row).
int presign_batch(const uint8_t       seed[32],
                  const uint32_t*     signer_ids,    // m entries, all > 0
                  uint32_t            m,             // # signers
                  uint32_t            slot_id_base,  // first slot id; row j gets base + j
                  uint32_t            n,             // # slots
                  CommitmentSlot*     commits_out,   // m*n entries
                  NonceSlot*          nonces_out)    // m*n entries
                  noexcept;

// Helper: compute the partial signature
//
//     z_i = d_i + e_i * rho_i + lambda_i * s_i * c   (mod n)
//
// where:
//   rho_i      — binding factor for signer i (RFC 9591 §4.4)
//   lambda_i   — Lagrange coefficient for signer i over the cohort
//   s_i        — signer i's secret share
//   c          — the challenge (RFC 9591 §4.5)
//
// All scalars are 32-byte big-endian. Output is 32-byte big-endian. Constant
// time in d_i, e_i, s_i.
//
// This is the per-signer ONLINE half of round-2; pre-sign supplies (d_i, e_i).
int partial_sign(const uint8_t d[32],
                 const uint8_t e[32],
                 const uint8_t rho[32],
                 const uint8_t lambda[32],
                 const uint8_t s[32],
                 const uint8_t c[32],
                 uint8_t       z_out[32]) noexcept;

}  // namespace kinet::crypto::frost

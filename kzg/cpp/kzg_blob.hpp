// SPDX-License-Identifier: Apache-2.0
//
// EIP-4844 EL-side blob ops. Backed by the vendored kinet-labs/c-kzg-4844 v2.1.7
// fork (FetchContent). The trusted setup is embedded at configure time from
// c-kzg-4844 v2.1.7 src/trusted_setup.txt and loaded once on first use.
//
// This header is internal to crypto/kzg — exposed only through the C ABI
// at c-abi/c_kzg.cpp. KZGSettings is opaque to consumers.
#pragma once

#include <cstdint>

namespace kinet-labs::crypto::kzg
{

/// Compute KZG commitment to a 128 KiB blob. Returns true on success.
/// Output: 48-byte compressed G1 point.
bool blob_to_kzg_commitment(uint8_t commitment[48], const uint8_t blob[131072]) noexcept;

/// Compute the KZG proof that opens `blob` at the Fiat-Shamir challenge
/// `commitment_bytes`. Returns true on success.
/// Output: 48-byte proof + 32-byte y (the blob's evaluation at the challenge).
bool compute_blob_kzg_proof(uint8_t proof[48], uint8_t y[32],
                            const uint8_t blob[131072],
                            const uint8_t commitment_bytes[48]) noexcept;

/// Verify that `proof` is a valid KZG proof for `commitment` over `blob`.
bool verify_blob_kzg_proof(const uint8_t blob[131072],
                           const uint8_t commitment[48],
                           const uint8_t proof[48]) noexcept;

/// Verify that all `(blob[i], commitment[i], proof[i])` triples are
/// consistent. Returns true iff every triple verifies.
bool verify_blob_kzg_proof_batch(const uint8_t* blobs,
                                 const uint8_t* commitments,
                                 const uint8_t* proofs,
                                 uint64_t n) noexcept;

/// Verify a (commitment, z, y, proof) tuple via c-kzg-4844 — alternate
/// path to the first-party kzg.cpp implementation. Used only by the EL
/// KAT harness; the EVM precompile keeps using the first-party body.
bool verify_kzg_proof_ckzg(const uint8_t commitment[48], const uint8_t z[32],
                           const uint8_t y[32], const uint8_t proof[48]) noexcept;

/// Compute the KZG proof for a single point opening (compute_kzg_proof KAT).
/// Output: 48-byte proof + 32-byte y_out.
bool compute_kzg_proof(uint8_t proof[48], uint8_t y_out[32],
                       const uint8_t blob[131072], const uint8_t z[32]) noexcept;

}  // namespace kinet-labs::crypto::kzg

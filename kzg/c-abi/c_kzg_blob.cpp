// =============================================================================
// kzg — C ABI shim for the EIP-4844 EL-side blob ops.
//
// This translation unit is intentionally separate from c_kzg.cpp so that
// nothing in cevm's call graph (which only references kzg_verify_proof)
// pulls these symbols out of the static archive. cevm's no-blst-in-
// production invariant requires the blob ops + the vendored kinet-labs/c-kzg-
// 4844 (which transitively references blst) to stay unreached by any
// production EVM linkage.
//
// Three operations:
//   * kzg_blob_to_commit   — block-builder: blob -> commitment
//   * kzg_commit_to_proof  — opens the blob at scalar z, returns (proof, y)
//   * kzg_verify_blob      — verify (blob, commitment, proof) tuple
//
// All three are backed by kinet-labs/c-kzg-4844 v2.1.7 with the mainnet
// trusted_setup.txt embedded at configure time and loaded once on first
// use. See cpp/kzg_blob.cpp for the loader and the c-kzg-4844 wiring.
// =============================================================================

#include "kinet_crypto.h"
#include "kzg_blob.hpp"

#include <cstddef>

extern "C" int kzg_blob_to_commit(const uint8_t blob[131072], uint8_t commit[48]) {
    return kinet-labs::crypto::kzg::blob_to_kzg_commitment(commit, blob)
        ? CRYPTO_OK : CRYPTO_ERR_INPUT;
}

extern "C" int kzg_commit_to_proof(const uint8_t blob[131072], const uint8_t z[32],
                                   uint8_t proof[48], uint8_t y[32]) {
    // The C-ABI signature names z, so we dispatch to the EIP-4844 §3.4
    // compute_kzg_proof(blob, z) -> (proof, y). The block-builder’s
    // compute_blob_kzg_proof (Fiat-Shamir-derived z) is exposed via the
    // first-party C++ surface (kinet-labs::crypto::kzg::compute_blob_kzg_proof)
    // and exercised by the consensus-spec KAT.
    return kinet-labs::crypto::kzg::compute_kzg_proof(proof, y, blob, z)
        ? CRYPTO_OK : CRYPTO_ERR_INPUT;
}

extern "C" int kzg_verify_blob(const uint8_t blob[131072],
                               const uint8_t commit[48],
                               const uint8_t proof[48]) {
    return kinet-labs::crypto::kzg::verify_blob_kzg_proof(blob, commit, proof)
        ? CRYPTO_OK : CRYPTO_ERR_VERIFY;
}

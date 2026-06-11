// =============================================================================
// kzg — C ABI shim for the EIP-4844 0x0a precompile (verify_proof only).
//
// This translation unit contains a single symbol — `kzg_verify_proof` —
// which is the EVM precompile surface called from cevm. Its body lives in
// cpp/kzg.cpp and uses the BLS12-381 pairing equation directly with the
// hard-coded [s]_2 setup point. No 4096-element trusted setup, no blst
// linkage required for production.
//
// The other three EIP-4844 ops (blob_to_commit, commit_to_proof,
// verify_blob) are EL-side only and live in c-abi/c_kzg_blob.cpp. That TU
// pulls in the vendored kinet-labs/c-kzg-4844 + blst, but cevm production
// archives never reference its symbols, so the no-blst-in-production
// invariant holds: nothing in cevm's call graph reaches `c_kzg_blob.cpp`.
// =============================================================================

#include "crypto.h"

#include <cstddef>

extern "C" int kzg_verify_proof(const uint8_t commit[48], const uint8_t z[32],
                                const uint8_t y[32], const uint8_t proof[48]) {
    if (commit == nullptr || z == nullptr || y == nullptr || proof == nullptr)
        return CRYPTO_ERR_INPUT;
    // Compute versioned hash from the commitment so the body's invariant
    // check is self-consistent.
    std::byte versioned_hash[cevm::crypto::SHA256_HASH_SIZE];
    cevm::crypto::sha256(versioned_hash,
                         reinterpret_cast<const std::byte*>(commit), 48);
    versioned_hash[0] = cevm::crypto::VERSIONED_HASH_VERSION_KZG;

    const bool ok = cevm::crypto::kzg_verify_proof(
        versioned_hash,
        reinterpret_cast<const std::byte*>(z),
        reinterpret_cast<const std::byte*>(y),
        reinterpret_cast<const std::byte*>(commit),
        reinterpret_cast<const std::byte*>(proof));
    return ok ? CRYPTO_OK : CRYPTO_ERR_VERIFY;
}

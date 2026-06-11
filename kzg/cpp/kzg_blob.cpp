// SPDX-License-Identifier: Apache-2.0
//
// EIP-4844 EL-side ops backed by kinet-labs/c-kzg-4844 v2.1.7.
// Loads the embedded mainnet trusted setup once, on first use.

#include "kzg_blob.hpp"
#include "trusted_setup.inc.h"

#include <cstdio>
#include <cstring>
#include <mutex>
#include <stdexcept>

extern "C" {
#include "ckzg.h"
}

namespace kinet-labs::crypto::kzg
{
namespace
{

/// One-shot trusted-setup loader. The KZGSettings is allocated once,
/// reused for the lifetime of the process. Thread-safe via call_once.
struct LoadedSettings
{
    KZGSettings inner{};
    bool loaded{false};

    LoadedSettings()
    {
        // fmemopen wraps the embedded byte array in a FILE* without I/O.
        // Cast away const because fmemopen signature is non-const-correct
        // on POSIX; the file is opened read-only ("r"), so no actual writes.
        FILE* fp = ::fmemopen(
            const_cast<unsigned char*>(TRUSTED_SETUP_BYTES),
            TRUSTED_SETUP_SIZE,
            "r");
        if (!fp) {
            return;
        }
        // precompute=0: skip the FK20 precomputed tables (saves ~150MB
        // RAM). EIP-4844 ops do not need them; they are an optimisation
        // for EIP-7594 cell-proof generation.
        const C_KZG_RET rc = ::load_trusted_setup_file(&inner, fp, 0);
        std::fclose(fp);
        loaded = (rc == C_KZG_OK);
    }

    ~LoadedSettings()
    {
        if (loaded) {
            ::free_trusted_setup(&inner);
        }
    }

    LoadedSettings(const LoadedSettings&) = delete;
    LoadedSettings& operator=(const LoadedSettings&) = delete;
};

const KZGSettings* settings() noexcept
{
    static LoadedSettings s;
    return s.loaded ? &s.inner : nullptr;
}

}  // namespace

bool blob_to_kzg_commitment(uint8_t commitment[48], const uint8_t blob[131072]) noexcept
{
    const KZGSettings* s = settings();
    if (!s) return false;
    KZGCommitment out;
    const C_KZG_RET rc = ::blob_to_kzg_commitment(
        &out,
        reinterpret_cast<const Blob*>(blob),
        s);
    if (rc != C_KZG_OK) return false;
    std::memcpy(commitment, out.bytes, 48);
    return true;
}

bool compute_blob_kzg_proof(uint8_t proof[48], uint8_t y[32],
                            const uint8_t blob[131072],
                            const uint8_t commitment_bytes[48]) noexcept
{
    // c-kzg-4844 compute_blob_kzg_proof returns only the proof (the
    // Fiat-Shamir challenge is derived from blob+commit so y is implicit).
    // Some test vectors expect a separate compute_kzg_proof(blob, z) — that
    // is exposed via compute_kzg_proof() below. Here we emit just the proof
    // and zero out y (the EIP-4844 EL surface only needs proof).
    const KZGSettings* s = settings();
    if (!s) return false;
    KZGProof proof_out;
    const C_KZG_RET rc = ::compute_blob_kzg_proof(
        &proof_out,
        reinterpret_cast<const Blob*>(blob),
        reinterpret_cast<const Bytes48*>(commitment_bytes),
        s);
    if (rc != C_KZG_OK) return false;
    std::memcpy(proof, proof_out.bytes, 48);
    if (y) std::memset(y, 0, 32);
    return true;
}

bool compute_kzg_proof(uint8_t proof[48], uint8_t y_out[32],
                       const uint8_t blob[131072], const uint8_t z[32]) noexcept
{
    const KZGSettings* s = settings();
    if (!s) return false;
    KZGProof proof_out;
    Bytes32 y_bytes;
    const C_KZG_RET rc = ::compute_kzg_proof(
        &proof_out,
        &y_bytes,
        reinterpret_cast<const Blob*>(blob),
        reinterpret_cast<const Bytes32*>(z),
        s);
    if (rc != C_KZG_OK) return false;
    std::memcpy(proof, proof_out.bytes, 48);
    std::memcpy(y_out, y_bytes.bytes, 32);
    return true;
}

bool verify_blob_kzg_proof(const uint8_t blob[131072],
                           const uint8_t commitment[48],
                           const uint8_t proof[48]) noexcept
{
    const KZGSettings* s = settings();
    if (!s) return false;
    bool ok = false;
    const C_KZG_RET rc = ::verify_blob_kzg_proof(
        &ok,
        reinterpret_cast<const Blob*>(blob),
        reinterpret_cast<const Bytes48*>(commitment),
        reinterpret_cast<const Bytes48*>(proof),
        s);
    return rc == C_KZG_OK && ok;
}

bool verify_blob_kzg_proof_batch(const uint8_t* blobs,
                                 const uint8_t* commitments,
                                 const uint8_t* proofs,
                                 uint64_t n) noexcept
{
    if (n == 0) return true;
    const KZGSettings* s = settings();
    if (!s) return false;
    bool ok = false;
    const C_KZG_RET rc = ::verify_blob_kzg_proof_batch(
        &ok,
        reinterpret_cast<const Blob*>(blobs),
        reinterpret_cast<const Bytes48*>(commitments),
        reinterpret_cast<const Bytes48*>(proofs),
        n,
        s);
    return rc == C_KZG_OK && ok;
}

bool verify_kzg_proof_ckzg(const uint8_t commitment[48], const uint8_t z[32],
                           const uint8_t y[32], const uint8_t proof[48]) noexcept
{
    const KZGSettings* s = settings();
    if (!s) return false;
    bool ok = false;
    const C_KZG_RET rc = ::verify_kzg_proof(
        &ok,
        reinterpret_cast<const Bytes48*>(commitment),
        reinterpret_cast<const Bytes32*>(z),
        reinterpret_cast<const Bytes32*>(y),
        reinterpret_cast<const Bytes48*>(proof),
        s);
    return rc == C_KZG_OK && ok;
}

}  // namespace kinet-labs::crypto::kzg

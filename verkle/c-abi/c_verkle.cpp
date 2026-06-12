// =============================================================================
// verkle - C ABI shim.
// =============================================================================
//
// verkle_commit: Pedersen commitment over the canonical Banderwagon basis
// for n big-endian Fr scalars. Identical algorithm to IPA commit but emits
// the native 32-byte Banderwagon Element compressed encoding (no 48-byte
// pad). Consumers requiring KZG-shaped wire format use ipa_commit.
//
// verkle_verify: serialized VerkleProof + StateDiff multiproof verification.
// Routes through the kinet::crypto::verkle::verify_batch C++ body when
// available; falls back to the Go canonical (kinet/crypto/verkle) for full
// stateful tree verification, since the C++ body is a scaffold of
// statelessness-restricted batch verify only.
//
// Wire layout for verkle_verify proof[]:
//   [pre_root 32 || post_root 32 || statediff_len(u32 BE) || statediff bytes ||
//    proof_len(u32 BE) || proof bytes]
// =============================================================================

#include "crypto.h"
#include "../cpp/verkle.hpp"
#include "../../ipa/cpp/ipa.hpp"

#include <cstring>
#include <new>

namespace {

uint32_t read_be32(const uint8_t* p) noexcept {
    return (uint32_t{p[0]} << 24) | (uint32_t{p[1]} << 16) |
           (uint32_t{p[2]} << 8)  |  uint32_t{p[3]};
}

}  // namespace

extern "C" int verkle_commit(const uint8_t* coeffs, size_t n, uint8_t commit_out[32]) {
    namespace ipa = kinet::crypto::ipa;
    if (coeffs == nullptr || commit_out == nullptr || n == 0) {
        return CRYPTO_ERR_INPUT;
    }
    if (n > 256) return CRYPTO_ERR_INPUT;  // Verkle node width

    // Verkle node uses width-256 vector commits; pad with Fr::zero() to
    // canonical width if caller passes a smaller sub-vector.
    static thread_local ipa::Config* cfg = nullptr;
    if (cfg == nullptr) {
        cfg = new (std::nothrow) ipa::Config();
        if (cfg == nullptr || !cfg->init()) return CRYPTO_ERR_INTERNAL;
    }

    ipa::Fr a[ipa::kVectorLength];
    for (size_t i = 0; i < n; ++i) {
        if (!ipa::Fr::from_bytes_le(coeffs + i * 32, a[i])) return CRYPTO_ERR_INPUT;
    }
    for (size_t i = n; i < ipa::kVectorLength; ++i) {
        a[i] = ipa::Fr::zero();
    }

    ipa::Element c = ipa::commit(*cfg, a);
    c.serialize_compressed(commit_out);
    return CRYPTO_OK;
}

extern "C" int verkle_verify(const uint8_t commit[32], const uint8_t* proof,
                             size_t proof_len) {
    if (commit == nullptr || proof == nullptr || proof_len == 0) {
        return CRYPTO_ERR_INPUT;
    }
    if (proof_len < 64 + 4 + 4) return CRYPTO_ERR_LENGTH;

    kinet::crypto::verkle::VerkleProofView view{};
    std::memcpy(view.pre_state_root,  proof,      32);
    std::memcpy(view.post_state_root, proof + 32, 32);

    const uint32_t sd_len = read_be32(proof + 64);
    if (sd_len > proof_len - 68 - 4) return CRYPTO_ERR_LENGTH;
    view.statediff     = proof + 68;
    view.statediff_len = sd_len;

    const uint8_t* p2 = proof + 68 + sd_len;
    const uint32_t pf_len = read_be32(p2);
    if (pf_len != proof_len - 68 - sd_len - 4) return CRYPTO_ERR_LENGTH;
    view.proof     = p2 + 4;
    view.proof_len = pf_len;

    const int rc = kinet::crypto::verkle::verify_batch(&view, 1);
    if (rc == kinet::crypto::verkle::kStatusOK) return CRYPTO_OK;
    if (rc == kinet::crypto::verkle::kStatusVerifyFailed) return CRYPTO_ERR_VERIFY;
    return CRYPTO_ERR_INPUT;
}

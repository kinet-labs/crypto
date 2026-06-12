#include "verkle.hpp"

namespace kinet::crypto::verkle {

int validate_batch_inputs(const VerkleProofView* proofs, size_t num_proofs) {
    if (proofs == nullptr || num_proofs == 0) return kStatusInvalidInput;
    for (size_t i = 0; i < num_proofs; ++i) {
        const auto& p = proofs[i];
        if (p.proof == nullptr || p.proof_len == 0) return kStatusInvalidInput;
        if (p.statediff == nullptr || p.statediff_len == 0) return kStatusInvalidInput;
        // pre_state_root and post_state_root are fixed-size by struct layout.
    }
    return kStatusOK;
}

int verify_batch(const VerkleProofView* proofs, size_t num_proofs) {
    int rc = validate_batch_inputs(proofs, num_proofs);
    if (rc != kStatusOK) return rc;
    return kStatusNotImplemented;
}

}  // namespace kinet::crypto::verkle

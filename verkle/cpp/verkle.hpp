// Copyright (C) 2025-2026, Kinet Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Verkle: tree commitments + multiproof verification.
//
// Reference: github.com/kinet-labs/crypto/verkle (Go) which re-exports
// github.com/ethereum/go-verkle.
//
// Status (this layer): scaffold. The byte-equal Verify body is blocked on
// the IPA + Banderwagon backends; until they land verify_batch returns
// kStatusNotImplemented after running input validation.

#pragma once

#include <cstddef>
#include <cstdint>

namespace kinet::crypto::verkle {

// VerkleProofView: serialized Verkle proof bytes (matches the upstream
// SerializeProof output).
struct VerkleProofView {
    const uint8_t* proof;       // serialized VerkleProof bytes
    size_t         proof_len;
    const uint8_t* statediff;   // serialized StateDiff bytes
    size_t         statediff_len;
    uint8_t pre_state_root[32];
    uint8_t post_state_root[32];
};

inline constexpr int kStatusOK             = 0;
inline constexpr int kStatusInvalidInput   = -1;
inline constexpr int kStatusVerifyFailed   = -3;
inline constexpr int kStatusNotImplemented = -5;

// validate_batch_inputs runs the input-validation contract.
//
// Rules:
//   - num_proofs > 0
//   - each proof has non-null/non-zero proof and statediff buffers
//   - state roots are exactly 32 bytes (enforced by struct layout)
int validate_batch_inputs(const VerkleProofView* proofs, size_t num_proofs);

// verify_batch checks num_proofs Verkle proofs in lockstep.
int verify_batch(const VerkleProofView* proofs, size_t num_proofs);

}  // namespace kinet::crypto::verkle

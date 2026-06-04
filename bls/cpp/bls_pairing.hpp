// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// BLS12-381 pairing public C++ surface.
//
// This file declares the production C++ API for pairing operations. The
// implementation in bls_pairing.cpp routes through the GPU (Metal/CUDA/WGSL)
// pairing pipeline once Stage 5 wiring lands. Until then, the test-time
// oracle implementation (in cpp/bls_pairing.cpp) links blst for unit
// validation; production builds substitute the GPU path.

#pragma once

#include <cstddef>
#include <cstdint>

namespace cevm::crypto::bls
{
// Compute e(P, Q) where:
//   P is an uncompressed G1 point  (96 bytes,  blst_p1_affine layout)
//   Q is an uncompressed G2 point  (192 bytes, blst_p2_affine layout)
// Output:
//   fp12_out is a 576-byte Fp12 element (blst_fp12 layout).
// Returns 0 on success.  Production builds dispatch to the on-device pairing
// pipeline (miller_loop + final_exp); identity inputs short-circuit to
// Fp12::one() per blst convention.
int pairing(const uint8_t  P_aff[96],
            const uint8_t  Q_aff[192],
            uint8_t        fp12_out[576]) noexcept;

// Aggregate verify: given N pairs (P_i, Q_i), check whether
//   prod_i e(P_i, Q_i)  ==  Fp12::one().
// Inputs:
//   pks   = N * 96  bytes  (G1 points, blst_p1_affine layout)
//   sigs  = N * 192 bytes  (G2 points, blst_p2_affine layout)
//   n     = number of pairs (>= 1)
// Returns:
//    0 if the aggregate verify succeeds (product equals one)
//    1 if it does not
//   <0 on error (malformed input)
int aggregate_verify(const uint8_t* pks,
                     const uint8_t* sigs,
                     size_t         n) noexcept;

}  // namespace cevm::crypto::bls

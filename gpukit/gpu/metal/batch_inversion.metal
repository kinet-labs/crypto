// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Skeleton kernel entry points for Montgomery batch inversion. v1.1 publishes
// stable function names so the metallib has them; the host driver returns
// NOTIMPL until the BLS Stage 3+ port wires this up.

#include <metal_stdlib>
using namespace metal;

kernel void batch_inv_secp256k1_pointwise_mul(
    uint gid [[ thread_position_in_grid ]]) { (void)gid; }

kernel void batch_inv_bn254_pointwise_mul(
    uint gid [[ thread_position_in_grid ]]) { (void)gid; }

kernel void batch_inv_bls12_381_pointwise_mul(
    uint gid [[ thread_position_in_grid ]]) { (void)gid; }

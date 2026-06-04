// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Skeleton entry point for parallel Merkle compose. Real impl v1.2.

#include <metal_stdlib>
using namespace metal;

kernel void merkle_compose_layer(
    uint gid [[ thread_position_in_grid ]]) { (void)gid; }

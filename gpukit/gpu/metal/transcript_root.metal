// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Skeleton entry point for batched Fiat-Shamir transcript -- v1.2 work.

#include <metal_stdlib>
using namespace metal;

kernel void transcript_root_finalize(
    uint gid [[ thread_position_in_grid ]]) { (void)gid; }

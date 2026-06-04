// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Inclusive prefix sum (scan).
//
// Two entry points are exported:
//   * prefix_sum_block_u32 / _u64    -- single-block scan (max 1024 lanes)
//   * prefix_sum_collect_u32 / _u64  -- absorb block-sums into successor blocks
//
// The host driver picks single-block dispatch when N <= 1024 and otherwise
// emits a two-pass scan (block-scan + serial collect of block sums + add-back).

#include <metal_stdlib>
using namespace metal;

#define BLOCK_SIZE 1024u

// ----- u32 single-block scan ------------------------------------------------

kernel void prefix_sum_block_u32(
    device const uint*    in           [[ buffer(0) ]],
    device       uint*    out          [[ buffer(1) ]],
    device       uint*    block_sums   [[ buffer(2) ]],
    constant     uint&    n            [[ buffer(3) ]],
    uint                  lid          [[ thread_position_in_threadgroup ]],
    uint                  bid          [[ threadgroup_position_in_grid ]])
{
    threadgroup uint scratch[BLOCK_SIZE];
    uint base = bid * BLOCK_SIZE;
    uint i = base + lid;
    scratch[lid] = (i < n) ? in[i] : 0u;
    threadgroup_barrier(mem_flags::mem_threadgroup);

    // Hillis-Steele inclusive scan within the block.
    for (uint d = 1; d < BLOCK_SIZE; d <<= 1) {
        uint v = scratch[lid];
        uint w = (lid >= d) ? scratch[lid - d] : 0u;
        threadgroup_barrier(mem_flags::mem_threadgroup);
        scratch[lid] = v + w;
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (i < n) out[i] = scratch[lid];
    if (lid == BLOCK_SIZE - 1u) {
        // Last lane writes the block's total sum.
        block_sums[bid] = scratch[lid];
    }
}

kernel void prefix_sum_collect_u32(
    device       uint*    out          [[ buffer(0) ]],
    device const uint*    block_prefix [[ buffer(1) ]],   // prefix sum of block_sums
    constant     uint&    n            [[ buffer(2) ]],
    uint                  gid          [[ thread_position_in_grid ]])
{
    if (gid >= n) return;
    uint b = gid / BLOCK_SIZE;
    if (b == 0u) return;
    out[gid] += block_prefix[b - 1u];
}

// ----- u64 single-block scan ------------------------------------------------

kernel void prefix_sum_block_u64(
    device const ulong*   in           [[ buffer(0) ]],
    device       ulong*   out          [[ buffer(1) ]],
    device       ulong*   block_sums   [[ buffer(2) ]],
    constant     uint&    n            [[ buffer(3) ]],
    uint                  lid          [[ thread_position_in_threadgroup ]],
    uint                  bid          [[ threadgroup_position_in_grid ]])
{
    threadgroup ulong scratch[BLOCK_SIZE];
    uint base = bid * BLOCK_SIZE;
    uint i = base + lid;
    scratch[lid] = (i < n) ? in[i] : 0ul;
    threadgroup_barrier(mem_flags::mem_threadgroup);

    for (uint d = 1; d < BLOCK_SIZE; d <<= 1) {
        ulong v = scratch[lid];
        ulong w = (lid >= d) ? scratch[lid - d] : 0ul;
        threadgroup_barrier(mem_flags::mem_threadgroup);
        scratch[lid] = v + w;
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (i < n) out[i] = scratch[lid];
    if (lid == BLOCK_SIZE - 1u) {
        block_sums[bid] = scratch[lid];
    }
}

kernel void prefix_sum_collect_u64(
    device       ulong*   out          [[ buffer(0) ]],
    device const ulong*   block_prefix [[ buffer(1) ]],
    constant     uint&    n            [[ buffer(2) ]],
    uint                  gid          [[ thread_position_in_grid ]])
{
    if (gid >= n) return;
    uint b = gid / BLOCK_SIZE;
    if (b == 0u) return;
    out[gid] += block_prefix[b - 1u];
}

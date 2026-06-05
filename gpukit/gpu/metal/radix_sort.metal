// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// LSD radix sort, 8-bit per pass. The kernel performs one pass:
//   * count: histogram a single byte position across lanes
//   * scan host-side  (driver runs prefix_sum_block_u32)
//   * scatter: emit each input to its bucket-ordered position
//
// Two passes per pass (count + scatter) for u32 means 8 dispatches; for u64
// it means 16. Stable because the scatter uses a per-bucket atomic counter
// keyed by a pre-scanned base offset.

#include <metal_stdlib>
using namespace metal;

#define RADIX 256u

kernel void radix_count_u32(
    device const uint*  in    [[ buffer(0) ]],
    device       atomic_uint* hist [[ buffer(1) ]], // 256 buckets
    constant     uint&  n     [[ buffer(2) ]],
    constant     uint&  shift [[ buffer(3) ]],
    uint                gid   [[ thread_position_in_grid ]])
{
    if (gid >= n) return;
    uint b = (in[gid] >> shift) & 0xFFu;
    atomic_fetch_add_explicit(&hist[b], 1u, memory_order_relaxed);
}

kernel void radix_scatter_u32(
    device const uint*  in    [[ buffer(0) ]],
    device const uint*  base  [[ buffer(1) ]], // exclusive scan of histogram (length 256)
    device       atomic_uint* cursor [[ buffer(2) ]], // local cursor per bucket, len 256
    device       uint*  out   [[ buffer(3) ]],
    constant     uint&  n     [[ buffer(4) ]],
    constant     uint&  shift [[ buffer(5) ]],
    uint                gid   [[ thread_position_in_grid ]])
{
    if (gid >= n) return;
    uint b = (in[gid] >> shift) & 0xFFu;
    uint off = atomic_fetch_add_explicit(&cursor[b], 1u, memory_order_relaxed);
    out[base[b] + off] = in[gid];
}

// u64 variants (same shape, wider value).

kernel void radix_count_u64(
    device const ulong* in    [[ buffer(0) ]],
    device       atomic_uint* hist [[ buffer(1) ]],
    constant     uint&  n     [[ buffer(2) ]],
    constant     uint&  shift [[ buffer(3) ]],
    uint                gid   [[ thread_position_in_grid ]])
{
    if (gid >= n) return;
    uint b = (uint)((in[gid] >> shift) & 0xFFul);
    atomic_fetch_add_explicit(&hist[b], 1u, memory_order_relaxed);
}

kernel void radix_scatter_u64(
    device const ulong* in    [[ buffer(0) ]],
    device const uint*  base  [[ buffer(1) ]],
    device       atomic_uint* cursor [[ buffer(2) ]],
    device       ulong* out   [[ buffer(3) ]],
    constant     uint&  n     [[ buffer(4) ]],
    constant     uint&  shift [[ buffer(5) ]],
    uint                gid   [[ thread_position_in_grid ]])
{
    if (gid >= n) return;
    uint b = (uint)((in[gid] >> shift) & 0xFFul);
    uint off = atomic_fetch_add_explicit(&cursor[b], 1u, memory_order_relaxed);
    out[base[b] + off] = in[gid];
}

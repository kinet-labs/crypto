// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// gpukit -- LSD radix sort, 8-bit per pass. count + scatter kernels.

@group(0) @binding(0) var<storage, read>       in_buf:   array<u32>;
@group(0) @binding(1) var<storage, read_write> hist_buf: array<atomic<u32>>;
@group(0) @binding(2) var<storage, read>       base_buf: array<u32>;
@group(0) @binding(3) var<storage, read_write> cursor_buf: array<atomic<u32>>;
@group(0) @binding(4) var<storage, read_write> out_buf:  array<u32>;
@group(0) @binding(5) var<uniform>             params:   vec2<u32>; // (n, shift)

@compute @workgroup_size(256)
fn radix_count_u32(@builtin(global_invocation_id) gid: vec3<u32>) {
    let n = params.x;
    let shift = params.y;
    if (gid.x >= n) { return; }
    let b = (in_buf[gid.x] >> shift) & 0xFFu;
    atomicAdd(&hist_buf[b], 1u);
}

@compute @workgroup_size(256)
fn radix_scatter_u32(@builtin(global_invocation_id) gid: vec3<u32>) {
    let n = params.x;
    let shift = params.y;
    if (gid.x >= n) { return; }
    let b = (in_buf[gid.x] >> shift) & 0xFFu;
    let off = atomicAdd(&cursor_buf[b], 1u);
    out_buf[base_buf[b] + off] = in_buf[gid.x];
}

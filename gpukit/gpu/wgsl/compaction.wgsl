// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// gpukit -- stream compaction. mark + scatter (scan dispatched separately).

@group(0) @binding(0) var<storage, read>       in_buf:   array<u32>;
@group(0) @binding(1) var<storage, read>       flags:    array<u32>; // packed bytes? use u32 per slot
@group(0) @binding(2) var<storage, read>       scan_buf: array<u32>;
@group(0) @binding(3) var<storage, read_write> out_buf:  array<u32>;
@group(0) @binding(4) var<uniform>             n_uniform: u32;
@group(0) @binding(5) var<storage, read_write> marks_buf: array<u32>;

@compute @workgroup_size(256)
fn compaction_mark_u32(@builtin(global_invocation_id) gid: vec3<u32>) {
    if (gid.x >= n_uniform) { return; }
    if (flags[gid.x] != 0u) { marks_buf[gid.x] = 1u; }
    else                    { marks_buf[gid.x] = 0u; }
}

@compute @workgroup_size(256)
fn compaction_scatter_u32(@builtin(global_invocation_id) gid: vec3<u32>) {
    if (gid.x >= n_uniform) { return; }
    if (flags[gid.x] == 0u) { return; }
    let dst = scan_buf[gid.x] - 1u;
    out_buf[dst] = in_buf[gid.x];
}

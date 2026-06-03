// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// gpukit -- inclusive prefix sum (Hillis-Steele within a workgroup of 1024).
// Two-pass dispatch: per-block scan + serial collect.

@group(0) @binding(0) var<storage, read>       in_buf:    array<u32>;
@group(0) @binding(1) var<storage, read_write> out_buf:   array<u32>;
@group(0) @binding(2) var<storage, read_write> block_sums: array<u32>;
@group(0) @binding(3) var<uniform>             n_uniform: u32;

var<workgroup> scratch: array<u32, 1024>;

@compute @workgroup_size(1024)
fn prefix_sum_block_u32(
    @builtin(local_invocation_id)   lid: vec3<u32>,
    @builtin(workgroup_id)          bid: vec3<u32>,
) {
    let i = bid.x * 1024u + lid.x;
    if (i < n_uniform) { scratch[lid.x] = in_buf[i]; }
    else               { scratch[lid.x] = 0u; }
    workgroupBarrier();

    var d: u32 = 1u;
    loop {
        if (d >= 1024u) { break; }
        let v = scratch[lid.x];
        var w: u32 = 0u;
        if (lid.x >= d) { w = scratch[lid.x - d]; }
        workgroupBarrier();
        scratch[lid.x] = v + w;
        workgroupBarrier();
        d = d << 1u;
    }

    if (i < n_uniform) { out_buf[i] = scratch[lid.x]; }
    if (lid.x == 1023u) { block_sums[bid.x] = scratch[lid.x]; }
}

@compute @workgroup_size(256)
fn prefix_sum_collect_u32(
    @builtin(global_invocation_id) gid: vec3<u32>,
) {
    if (gid.x >= n_uniform) { return; }
    let b = gid.x / 1024u;
    if (b == 0u) { return; }
    out_buf[gid.x] = out_buf[gid.x] + block_sums[b - 1u];
}

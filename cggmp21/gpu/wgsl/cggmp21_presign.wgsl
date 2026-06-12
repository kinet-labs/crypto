// CGGMP21 batched pre-signing — WGSL compute shader scaffold.
// Same status-0xFF sentinel pattern as the Metal kernel; the body lands
// when the 2048-bit Karatsuba modexp primitive ships.

@group(0) @binding(0) var<storage, read>       seed         : array<u32, 8>;
@group(0) @binding(1) var<storage, read>       signer_ids   : array<u32>;
@group(0) @binding(2) var<uniform>             params       : vec4<u32>;  // (m, slot_id_base, n_slots, _)
@group(0) @binding(3) var<storage, read_write> records_out  : array<u32>;

const REC_U32 : u32 = 411u;  // sizeof(PresignRecord) / 4 = 1645 bytes / 4 (rounded)

@compute @workgroup_size(64)
fn cggmp21_presign_main(@builtin(global_invocation_id) gid : vec3<u32>) {
    let total = params.x * params.z;
    if (gid.x >= total) { return; }

    let signer_id = signer_ids[gid.x / params.z];
    if (signer_id == 0u) { return; }

    let base = gid.x * REC_U32;
    // Sentinel: a compact marker the host polyfill / driver can detect.
    records_out[base] = 0xFFFFFFFFu;
}

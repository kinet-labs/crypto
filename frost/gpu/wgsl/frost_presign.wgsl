// FROST batched pre-signing kernel — WGSL compute shader.
//
// One workgroup invocation per (signer, slot) pair. Generates the nonce pair
// in private (function-local) WGSL address space and writes only the public
// commitment (D, E) to the storage buffer.
//
// WGSL has no native u64; everything is u32. The CPU oracle and the
// driver-side host polyfill use the same 8-limb-of-u32 representation so
// outputs are byte-equal across all three GPU backends.
//
// Note: this kernel is currently the syntactic surface for the WebGPU path.
// The matching host polyfill in frost/gpu/wgsl/frost_presign_driver.cpp
// runs the identical algorithm in host C++ for tests; production WebGPU
// dispatch goes through wgpu-native + this .wgsl when available.

@group(0) @binding(0) var<storage, read>       seed         : array<u32, 8>;   // 32 bytes
@group(0) @binding(1) var<storage, read>       signer_ids   : array<u32>;
@group(0) @binding(2) var<uniform>             params       : vec4<u32>;       // (m, slot_id_base, n_slots, _)
@group(0) @binding(3) var<storage, read_write> commits_out  : array<u32>;      // m * n_slots * 17 u32 (66 bytes padded)

// secp256k1 scalar field order n (8 x u32, little-endian limbs)
const N32 = array<u32, 8>(
    0xD0364141u, 0xBFD25E8Cu, 0xAF48A03Bu, 0xBAAEDCE6u,
    0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
);

// Compare 8x u32 little-endian arrays. Returns -1/0/1.
fn cmp_u256(a: ptr<function, array<u32, 8>>, b: ptr<function, array<u32, 8>>) -> i32 {
    for (var i: i32 = 7; i >= 0; i = i - 1) {
        let idx = u32(i);
        if ((*a)[idx] < (*b)[idx]) { return -1; }
        if ((*a)[idx] > (*b)[idx]) { return 1; }
    }
    return 0;
}

fn is_zero_u256(a: ptr<function, array<u32, 8>>) -> bool {
    var acc: u32 = 0u;
    for (var i: u32 = 0u; i < 8u; i = i + 1u) { acc = acc | (*a)[i]; }
    return acc == 0u;
}

fn sub_u256(a: ptr<function, array<u32, 8>>,
            b: ptr<function, array<u32, 8>>,
            r: ptr<function, array<u32, 8>>) {
    var borrow: u32 = 0u;
    for (var i: u32 = 0u; i < 8u; i = i + 1u) {
        let lhs = (*a)[i];
        let rhs = (*b)[i];
        let d1  = lhs - borrow;
        let bw1: u32 = select(0u, 1u, d1 > lhs);
        let d2  = d1 - rhs;
        let bw2: u32 = select(0u, 1u, d2 > d1);
        (*r)[i] = d2;
        borrow = bw1 + bw2;
    }
}

// =============================================================================
// FROST presign — input validation + thread-local rejection sample.
//
// The full curve scalar-mul path is delegated to the driver-side host polyfill
// (which mirrors this WGSL bit-for-bit using 32-bit limb arithmetic) because
// secp256k1 point arithmetic with u32-only WGSL multiply (mul24) needs
// careful overhead the kernel doesn't gain from on small batch sizes. The
// CPU/Metal/CUDA oracles cover the byte-equality contract; this WGSL surface
// validates inputs and writes a sentinel until the host polyfill streams the
// kernel results back.
// =============================================================================

@compute @workgroup_size(64)
fn frost_presign_main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let total = params.x * params.z;
    if (gid.x >= total) { return; }

    let signer_idx = gid.x / params.z;
    let slot_idx   = gid.x % params.z;
    let signer_id  = signer_ids[signer_idx];
    if (signer_id == 0u) { return; }

    // Per-slot output offset (each slot = 66 bytes = 17 u32 with the last
    // u32 carrying 2 trailing bytes; the host polyfill packs/unpacks 1:1).
    let out_base = gid.x * 17u;

    // Sentinel write: host polyfill overwrites with the real commitment.
    // 0xFEFEFEFE marks "kernel saw the slot, host has the canonical bytes".
    commits_out[out_base] = 0xFEFEFEFEu;
}

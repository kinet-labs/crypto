// WGSL compute kernels for the BLS12-381 Fp tower (Stage 1 parity).
// Each kernel processes one element per dispatch (1×N grid, workgroup_size(1))
// to preserve byte-determinism across backends.
//
// Concatenated by the host driver onto bls_fp_ops.wgsl + bls_fp2.wgsl +
// bls_fp6.wgsl + bls_fp12.wgsl in that order.

@group(0) @binding(0) var<storage, read>       in_a: array<u32>;
@group(0) @binding(1) var<storage, read>       in_b: array<u32>;
@group(0) @binding(2) var<storage, read_write> out:  array<u32>;
@group(0) @binding(3) var<uniform>             params: vec4<u32>; // [count, _, _, _]

// Helpers — load/store sized arrays from the flat global storage buffers.
fn load_fp(buf_ptr: u32, base: u32) -> array<u32, 12> {
    var r: array<u32, 12>;
    if (buf_ptr == 0u) {
        for (var i = 0u; i < 12u; i = i + 1u) { r[i] = in_a[base + i]; }
    } else {
        for (var i = 0u; i < 12u; i = i + 1u) { r[i] = in_b[base + i]; }
    }
    return r;
}
fn store_fp(base: u32, v: array<u32, 12>) {
    for (var i = 0u; i < 12u; i = i + 1u) { out[base + i] = v[i]; }
}
fn load_fp2(buf_ptr: u32, base: u32) -> array<u32, 24> {
    var r: array<u32, 24>;
    if (buf_ptr == 0u) {
        for (var i = 0u; i < 24u; i = i + 1u) { r[i] = in_a[base + i]; }
    } else {
        for (var i = 0u; i < 24u; i = i + 1u) { r[i] = in_b[base + i]; }
    }
    return r;
}
fn store_fp2(base: u32, v: array<u32, 24>) {
    for (var i = 0u; i < 24u; i = i + 1u) { out[base + i] = v[i]; }
}
fn load_fp6(buf_ptr: u32, base: u32) -> array<u32, 72> {
    var r: array<u32, 72>;
    if (buf_ptr == 0u) {
        for (var i = 0u; i < 72u; i = i + 1u) { r[i] = in_a[base + i]; }
    } else {
        for (var i = 0u; i < 72u; i = i + 1u) { r[i] = in_b[base + i]; }
    }
    return r;
}
fn store_fp6(base: u32, v: array<u32, 72>) {
    for (var i = 0u; i < 72u; i = i + 1u) { out[base + i] = v[i]; }
}
fn load_fp12(buf_ptr: u32, base: u32) -> array<u32, 144> {
    var r: array<u32, 144>;
    if (buf_ptr == 0u) {
        for (var i = 0u; i < 144u; i = i + 1u) { r[i] = in_a[base + i]; }
    } else {
        for (var i = 0u; i < 144u; i = i + 1u) { r[i] = in_b[base + i]; }
    }
    return r;
}
fn store_fp12(base: u32, v: array<u32, 144>) {
    for (var i = 0u; i < 144u; i = i + 1u) { out[base + i] = v[i]; }
}

// =============================================================================
// Fp diagnostic — raw fp_inv on c0 of Fp2 input.
// =============================================================================

@compute @workgroup_size(1) fn k_fp_inv_diag(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 24u;
    let c0 = load_fp(0u, off);
    let r = fp_inv(c0);
    store_fp(off, r);
    for (var k = 12u; k < 24u; k = k + 1u) { out[off + k] = 0u; }
}

// =============================================================================
// Fp2 kernels
// =============================================================================

@compute @workgroup_size(1) fn k_fp2_add(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 24u;
    store_fp2(off, fp2_add(load_fp2(0u, off), load_fp2(1u, off)));
}
@compute @workgroup_size(1) fn k_fp2_sub(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 24u;
    store_fp2(off, fp2_sub(load_fp2(0u, off), load_fp2(1u, off)));
}
@compute @workgroup_size(1) fn k_fp2_mul(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 24u;
    store_fp2(off, fp2_mul(load_fp2(0u, off), load_fp2(1u, off)));
}
@compute @workgroup_size(1) fn k_fp2_sqr(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 24u;
    store_fp2(off, fp2_sqr(load_fp2(0u, off)));
}
@compute @workgroup_size(1) fn k_fp2_inv(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 24u;
    store_fp2(off, fp2_inv(load_fp2(0u, off)));
}
@compute @workgroup_size(1) fn k_fp2_conj(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 24u;
    store_fp2(off, fp2_conj(load_fp2(0u, off)));
}

// =============================================================================
// Fp6 kernels
// =============================================================================

@compute @workgroup_size(1) fn k_fp6_add(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 72u;
    store_fp6(off, fp6_add(load_fp6(0u, off), load_fp6(1u, off)));
}
@compute @workgroup_size(1) fn k_fp6_sub(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 72u;
    store_fp6(off, fp6_sub(load_fp6(0u, off), load_fp6(1u, off)));
}
@compute @workgroup_size(1) fn k_fp6_mul(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 72u;
    store_fp6(off, fp6_mul(load_fp6(0u, off), load_fp6(1u, off)));
}
@compute @workgroup_size(1) fn k_fp6_sqr(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 72u;
    store_fp6(off, fp6_sqr(load_fp6(0u, off)));
}
@compute @workgroup_size(1) fn k_fp6_inv(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 72u;
    store_fp6(off, fp6_inv(load_fp6(0u, off)));
}

// =============================================================================
// Fp12 kernels
// =============================================================================

@compute @workgroup_size(1) fn k_fp12_add(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 144u;
    store_fp12(off, fp12_add(load_fp12(0u, off), load_fp12(1u, off)));
}
@compute @workgroup_size(1) fn k_fp12_sub(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 144u;
    store_fp12(off, fp12_sub(load_fp12(0u, off), load_fp12(1u, off)));
}
@compute @workgroup_size(1) fn k_fp12_mul(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 144u;
    store_fp12(off, fp12_mul(load_fp12(0u, off), load_fp12(1u, off)));
}
@compute @workgroup_size(1) fn k_fp12_sqr(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 144u;
    store_fp12(off, fp12_sqr(load_fp12(0u, off)));
}
@compute @workgroup_size(1) fn k_fp12_inv(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 144u;
    store_fp12(off, fp12_inv(load_fp12(0u, off)));
}
@compute @workgroup_size(1) fn k_fp12_conj(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 144u;
    store_fp12(off, fp12_conj(load_fp12(0u, off)));
}
@compute @workgroup_size(1) fn k_fp12_cyclo_sqr(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 144u;
    store_fp12(off, fp12_cyclotomic_sqr(load_fp12(0u, off)));
}

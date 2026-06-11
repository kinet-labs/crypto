// WGSL compute kernels for the BLS12-381 Fp tower (Stage 1 + 4 parity).
// Each kernel processes one element per dispatch (1×N grid, workgroup_size(1))
// to preserve byte-determinism across backends.
//
// Concatenated by the host driver onto bls_fp_ops.wgsl + bls_fp2.wgsl +
// bls_fp6.wgsl + bls_fp12.wgsl in that order.
//
// Upper-tower kernels (fp6_inv, fp12_*) call the out-pointer (_p) form so
// the call tree never materialises a returned array<u32, 72> or
// array<u32, 144> on the function-call stack.

@group(0) @binding(0) var<storage, read>       in_a: array<u32>;
@group(0) @binding(1) var<storage, read>       in_b: array<u32>;
@group(0) @binding(2) var<storage, read_write> out:  array<u32>;
@group(0) @binding(3) var<uniform>             params: vec4<u32>; // [count, _, _, _]

// Helpers — load/store sized arrays from the flat global storage buffers.
fn load_fp_into(buf_ptr: u32, base: u32, dst: ptr<function, array<u32, 12>>) {
    if (buf_ptr == 0u) {
        for (var i = 0u; i < 12u; i = i + 1u) { (*dst)[i] = in_a[base + i]; }
    } else {
        for (var i = 0u; i < 12u; i = i + 1u) { (*dst)[i] = in_b[base + i]; }
    }
}
fn store_fp_from(base: u32, src: ptr<function, array<u32, 12>>) {
    for (var i = 0u; i < 12u; i = i + 1u) { out[base + i] = (*src)[i]; }
}
fn load_fp2_into(buf_ptr: u32, base: u32, dst: ptr<function, array<u32, 24>>) {
    if (buf_ptr == 0u) {
        for (var i = 0u; i < 24u; i = i + 1u) { (*dst)[i] = in_a[base + i]; }
    } else {
        for (var i = 0u; i < 24u; i = i + 1u) { (*dst)[i] = in_b[base + i]; }
    }
}
fn store_fp2_from(base: u32, src: ptr<function, array<u32, 24>>) {
    for (var i = 0u; i < 24u; i = i + 1u) { out[base + i] = (*src)[i]; }
}
fn load_fp6_into(buf_ptr: u32, base: u32, dst: ptr<function, array<u32, 72>>) {
    if (buf_ptr == 0u) {
        for (var i = 0u; i < 72u; i = i + 1u) { (*dst)[i] = in_a[base + i]; }
    } else {
        for (var i = 0u; i < 72u; i = i + 1u) { (*dst)[i] = in_b[base + i]; }
    }
}
fn store_fp6_from(base: u32, src: ptr<function, array<u32, 72>>) {
    for (var i = 0u; i < 72u; i = i + 1u) { out[base + i] = (*src)[i]; }
}
fn load_fp12_into(buf_ptr: u32, base: u32, dst: ptr<function, array<u32, 144>>) {
    if (buf_ptr == 0u) {
        for (var i = 0u; i < 144u; i = i + 1u) { (*dst)[i] = in_a[base + i]; }
    } else {
        for (var i = 0u; i < 144u; i = i + 1u) { (*dst)[i] = in_b[base + i]; }
    }
}
fn store_fp12_from(base: u32, src: ptr<function, array<u32, 144>>) {
    for (var i = 0u; i < 144u; i = i + 1u) { out[base + i] = (*src)[i]; }
}

// =============================================================================
// Fp diagnostic — raw fp_inv on c0 of Fp2 input.
// =============================================================================

@compute @workgroup_size(1) fn k_fp_inv_diag(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 24u;
    var c0: array<u32, 12>;
    load_fp_into(0u, off, &c0);
    var r = fp_inv(c0);
    store_fp_from(off, &r);
    for (var k = 12u; k < 24u; k = k + 1u) { out[off + k] = 0u; }
}

// =============================================================================
// Fp2 kernels
// =============================================================================

@compute @workgroup_size(1) fn k_fp2_add(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 24u;
    var a: array<u32, 24>; load_fp2_into(0u, off, &a);
    var b: array<u32, 24>; load_fp2_into(1u, off, &b);
    var r: array<u32, 24>; fp2_add_p(&a, &b, &r);
    store_fp2_from(off, &r);
}
@compute @workgroup_size(1) fn k_fp2_sub(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 24u;
    var a: array<u32, 24>; load_fp2_into(0u, off, &a);
    var b: array<u32, 24>; load_fp2_into(1u, off, &b);
    var r: array<u32, 24>; fp2_sub_p(&a, &b, &r);
    store_fp2_from(off, &r);
}
@compute @workgroup_size(1) fn k_fp2_mul(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 24u;
    var a: array<u32, 24>; load_fp2_into(0u, off, &a);
    var b: array<u32, 24>; load_fp2_into(1u, off, &b);
    var r: array<u32, 24>; fp2_mul_p(&a, &b, &r);
    store_fp2_from(off, &r);
}
@compute @workgroup_size(1) fn k_fp2_sqr(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 24u;
    var a: array<u32, 24>; load_fp2_into(0u, off, &a);
    var r: array<u32, 24>; fp2_sqr_p(&a, &r);
    store_fp2_from(off, &r);
}
@compute @workgroup_size(1) fn k_fp2_inv(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 24u;
    var a: array<u32, 24>; load_fp2_into(0u, off, &a);
    var r: array<u32, 24>; fp2_inv_p(&a, &r);
    store_fp2_from(off, &r);
}
@compute @workgroup_size(1) fn k_fp2_conj(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 24u;
    var a: array<u32, 24>; load_fp2_into(0u, off, &a);
    var r: array<u32, 24>; fp2_conj_p(&a, &r);
    store_fp2_from(off, &r);
}

// =============================================================================
// Fp6 kernels
// =============================================================================

@compute @workgroup_size(1) fn k_fp6_add(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 72u;
    var a: array<u32, 72>; load_fp6_into(0u, off, &a);
    var b: array<u32, 72>; load_fp6_into(1u, off, &b);
    var r: array<u32, 72>; fp6_add_p(&a, &b, &r);
    store_fp6_from(off, &r);
}
@compute @workgroup_size(1) fn k_fp6_sub(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 72u;
    var a: array<u32, 72>; load_fp6_into(0u, off, &a);
    var b: array<u32, 72>; load_fp6_into(1u, off, &b);
    var r: array<u32, 72>; fp6_sub_p(&a, &b, &r);
    store_fp6_from(off, &r);
}
@compute @workgroup_size(1) fn k_fp6_mul(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 72u;
    var a: array<u32, 72>; load_fp6_into(0u, off, &a);
    var b: array<u32, 72>; load_fp6_into(1u, off, &b);
    var r: array<u32, 72>; fp6_mul_p(&a, &b, &r);
    store_fp6_from(off, &r);
}
@compute @workgroup_size(1) fn k_fp6_sqr(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 72u;
    var a: array<u32, 72>; load_fp6_into(0u, off, &a);
    var r: array<u32, 72>; fp6_sqr_p(&a, &r);
    store_fp6_from(off, &r);
}
@compute @workgroup_size(1) fn k_fp6_inv(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 72u;
    var a: array<u32, 72>; load_fp6_into(0u, off, &a);
    var r: array<u32, 72>; fp6_inv_p(&a, &r);
    store_fp6_from(off, &r);
}

// =============================================================================
// Fp12 kernels
//
// Each kernel runs at workgroup_size(1) with one dispatch per element, so
// we keep the 144 x u32 operands in private storage. This keeps the
// function-call stack budget under AGXMetalG13X's per-thread limit when
// the karatsuba/inversion call tree (fp6_inv inside fp12_inv) is traversed.
// =============================================================================

var<private> g_fp12_a: array<u32, 144>;
var<private> g_fp12_b: array<u32, 144>;
var<private> g_fp12_r: array<u32, 144>;

fn load_fp12_priv(buf_ptr: u32, base: u32, dst: ptr<private, array<u32, 144>>) {
    if (buf_ptr == 0u) {
        for (var i = 0u; i < 144u; i = i + 1u) { (*dst)[i] = in_a[base + i]; }
    } else {
        for (var i = 0u; i < 144u; i = i + 1u) { (*dst)[i] = in_b[base + i]; }
    }
}
fn store_fp12_priv(base: u32, src: ptr<private, array<u32, 144>>) {
    for (var i = 0u; i < 144u; i = i + 1u) { out[base + i] = (*src)[i]; }
}

@compute @workgroup_size(1) fn k_fp12_add(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 144u;
    load_fp12_priv(0u, off, &g_fp12_a);
    load_fp12_priv(1u, off, &g_fp12_b);
    fp12_add_priv(&g_fp12_a, &g_fp12_b, &g_fp12_r);
    store_fp12_priv(off, &g_fp12_r);
}
@compute @workgroup_size(1) fn k_fp12_sub(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 144u;
    load_fp12_priv(0u, off, &g_fp12_a);
    load_fp12_priv(1u, off, &g_fp12_b);
    fp12_sub_priv(&g_fp12_a, &g_fp12_b, &g_fp12_r);
    store_fp12_priv(off, &g_fp12_r);
}
@compute @workgroup_size(1) fn k_fp12_mul(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 144u;
    load_fp12_priv(0u, off, &g_fp12_a);
    load_fp12_priv(1u, off, &g_fp12_b);
    fp12_mul_priv(&g_fp12_a, &g_fp12_b, &g_fp12_r);
    store_fp12_priv(off, &g_fp12_r);
}
@compute @workgroup_size(1) fn k_fp12_sqr(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 144u;
    load_fp12_priv(0u, off, &g_fp12_a);
    fp12_sqr_priv(&g_fp12_a, &g_fp12_r);
    store_fp12_priv(off, &g_fp12_r);
}
@compute @workgroup_size(1) fn k_fp12_inv(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 144u;
    load_fp12_priv(0u, off, &g_fp12_a);
    fp12_inv_priv(&g_fp12_a, &g_fp12_r);
    store_fp12_priv(off, &g_fp12_r);
}
@compute @workgroup_size(1) fn k_fp12_conj(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 144u;
    load_fp12_priv(0u, off, &g_fp12_a);
    fp12_conj_priv(&g_fp12_a, &g_fp12_r);
    store_fp12_priv(off, &g_fp12_r);
}
@compute @workgroup_size(1) fn k_fp12_cyclo_sqr(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; if (i >= params.x) { return; }
    let off = i * 144u;
    load_fp12_priv(0u, off, &g_fp12_a);
    fp12_cyclotomic_sqr_priv(&g_fp12_a, &g_fp12_r);
    store_fp12_priv(off, &g_fp12_r);
}

// WGSL peer of bls_fp2.metal. Fp2 represented as 24 x u32 (c0 in [0..12), c1 in [12..24)).
// Byte layout matches blst_fp2: 96 bytes.
//
// Inputs are passed by ptr<function, array<u32, N>> AND outputs are written
// through ptr<function, array<u32, N>>. Returning Fp2/Fp6/Fp12 by value
// materialises a stack copy at every call site; the karatsuba/inversion call
// tree on the upper tower (fp6_inv / fp12 mul/sqr/inv/conj/cyclo_sqr) then
// blows AGXMetalG13X's function-call stack budget. Out-pointer form keeps
// every intermediate in a single named slot the caller already owns.
// Same arithmetic as Metal.

fn fp2_get_c0(a: ptr<function, array<u32, 24>>) -> array<u32, 12> {
    var r: array<u32, 12>;
    for (var i = 0u; i < 12u; i = i + 1u) { r[i] = (*a)[i]; }
    return r;
}
fn fp2_get_c1(a: ptr<function, array<u32, 24>>) -> array<u32, 12> {
    var r: array<u32, 12>;
    for (var i = 0u; i < 12u; i = i + 1u) { r[i] = (*a)[12u + i]; }
    return r;
}
fn fp2_pack(c0: array<u32, 12>, c1: array<u32, 12>) -> array<u32, 24> {
    var r: array<u32, 24>;
    for (var i = 0u; i < 12u; i = i + 1u) { r[i] = c0[i]; r[12u + i] = c1[i]; }
    return r;
}
fn fp2_zero() -> array<u32, 24> {
    var r: array<u32, 24>;
    for (var i = 0u; i < 24u; i = i + 1u) { r[i] = 0u; }
    return r;
}
fn fp2_one_v() -> array<u32, 24> {
    var r: array<u32, 24>;
    for (var i = 0u; i < 12u; i = i + 1u) { r[i] = BLS_R[i]; r[12u + i] = 0u; }
    return r;
}
fn fp2_is_zero(a: ptr<function, array<u32, 24>>) -> bool {
    var acc = 0u;
    for (var i = 0u; i < 24u; i = i + 1u) { acc = acc | (*a)[i]; }
    return acc == 0u;
}

// ---------- Out-pointer Fp2 primitives (used by upper tower) ----------

fn fp2_add_p(a: ptr<function, array<u32, 24>>, b: ptr<function, array<u32, 24>>,
             out: ptr<function, array<u32, 24>>) {
    var ac0 = fp2_get_c0(a); var ac1 = fp2_get_c1(a);
    var bc0 = fp2_get_c0(b); var bc1 = fp2_get_c1(b);
    let r0 = fp_add(ac0, bc0);
    let r1 = fp_add(ac1, bc1);
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = r0[i]; (*out)[12u + i] = r1[i]; }
}
fn fp2_sub_p(a: ptr<function, array<u32, 24>>, b: ptr<function, array<u32, 24>>,
             out: ptr<function, array<u32, 24>>) {
    var ac0 = fp2_get_c0(a); var ac1 = fp2_get_c1(a);
    var bc0 = fp2_get_c0(b); var bc1 = fp2_get_c1(b);
    let r0 = fp_sub(ac0, bc0);
    let r1 = fp_sub(ac1, bc1);
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = r0[i]; (*out)[12u + i] = r1[i]; }
}
fn fp2_neg_p(a: ptr<function, array<u32, 24>>, out: ptr<function, array<u32, 24>>) {
    var ac0 = fp2_get_c0(a); var ac1 = fp2_get_c1(a);
    let r0 = fp_neg(ac0);
    let r1 = fp_neg(ac1);
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = r0[i]; (*out)[12u + i] = r1[i]; }
}
fn fp2_mul_p(a: ptr<function, array<u32, 24>>, b: ptr<function, array<u32, 24>>,
             out: ptr<function, array<u32, 24>>) {
    var a0 = fp2_get_c0(a);
    var a1 = fp2_get_c1(a);
    var b0 = fp2_get_c0(b);
    var b1 = fp2_get_c1(b);
    let aa = fp_mul(a0, b0);
    let bb = fp_mul(a1, b1);
    let sa = fp_add(a0, a1);
    let sb = fp_add(b0, b1);
    let cross = fp_mul(sa, sb);
    let r0 = fp_sub(aa, bb);
    let r1 = fp_sub(fp_sub(cross, aa), bb);
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = r0[i]; (*out)[12u + i] = r1[i]; }
}
fn fp2_sqr_p(a: ptr<function, array<u32, 24>>, out: ptr<function, array<u32, 24>>) {
    var a0 = fp2_get_c0(a);
    var a1 = fp2_get_c1(a);
    let ab  = fp_mul(a0, a1);
    let sum = fp_add(a0, a1);
    let dif = fp_sub(a0, a1);
    let r0 = fp_mul(sum, dif);
    let r1 = fp_add(ab, ab);
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = r0[i]; (*out)[12u + i] = r1[i]; }
}
fn fp2_conj_p(a: ptr<function, array<u32, 24>>, out: ptr<function, array<u32, 24>>) {
    var ac0 = fp2_get_c0(a);
    var ac1 = fp2_get_c1(a);
    let r1 = fp_neg(ac1);
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = ac0[i]; (*out)[12u + i] = r1[i]; }
}
fn fp2_inv_p(a: ptr<function, array<u32, 24>>, out: ptr<function, array<u32, 24>>) {
    var a0 = fp2_get_c0(a);
    var a1 = fp2_get_c1(a);
    let t0 = fp_sqr(a0);
    let t1 = fp_sqr(a1);
    let norm = fp_add(t0, t1);
    let ni = fp_inv(norm);
    let r0 = fp_mul(a0, ni);
    let r1 = fp_neg(fp_mul(a1, ni));
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = r0[i]; (*out)[12u + i] = r1[i]; }
}
fn fp2_mul_by_1_plus_u_p(a: ptr<function, array<u32, 24>>,
                         out: ptr<function, array<u32, 24>>) {
    var a0 = fp2_get_c0(a);
    var a1 = fp2_get_c1(a);
    let r0 = fp_sub(a0, a1);
    let r1 = fp_add(a0, a1);
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = r0[i]; (*out)[12u + i] = r1[i]; }
}
fn fp2_frobenius_p(a: ptr<function, array<u32, 24>>, n: u32,
                   out: ptr<function, array<u32, 24>>) {
    if ((n & 1u) == 1u) { fp2_conj_p(a, out); return; }
    for (var i = 0u; i < 24u; i = i + 1u) { (*out)[i] = (*a)[i]; }
}

// ---------- Legacy by-value Fp2 helpers (still used by Stage-1 kernels) ----------

fn fp2_add(a: ptr<function, array<u32, 24>>, b: ptr<function, array<u32, 24>>) -> array<u32, 24> {
    var r: array<u32, 24>;
    fp2_add_p(a, b, &r);
    return r;
}
fn fp2_sub(a: ptr<function, array<u32, 24>>, b: ptr<function, array<u32, 24>>) -> array<u32, 24> {
    var r: array<u32, 24>;
    fp2_sub_p(a, b, &r);
    return r;
}
fn fp2_neg(a: ptr<function, array<u32, 24>>) -> array<u32, 24> {
    var r: array<u32, 24>;
    fp2_neg_p(a, &r);
    return r;
}
fn fp2_mul(a: ptr<function, array<u32, 24>>, b: ptr<function, array<u32, 24>>) -> array<u32, 24> {
    var r: array<u32, 24>;
    fp2_mul_p(a, b, &r);
    return r;
}
fn fp2_sqr(a: ptr<function, array<u32, 24>>) -> array<u32, 24> {
    var r: array<u32, 24>;
    fp2_sqr_p(a, &r);
    return r;
}
fn fp2_conj(a: ptr<function, array<u32, 24>>) -> array<u32, 24> {
    var r: array<u32, 24>;
    fp2_conj_p(a, &r);
    return r;
}
fn fp2_inv(a: ptr<function, array<u32, 24>>) -> array<u32, 24> {
    var r: array<u32, 24>;
    fp2_inv_p(a, &r);
    return r;
}
fn fp2_frobenius(a: ptr<function, array<u32, 24>>, n: u32) -> array<u32, 24> {
    var r: array<u32, 24>;
    fp2_frobenius_p(a, n, &r);
    return r;
}
fn fp2_mul_by_1_plus_u(a: ptr<function, array<u32, 24>>) -> array<u32, 24> {
    var r: array<u32, 24>;
    fp2_mul_by_1_plus_u_p(a, &r);
    return r;
}

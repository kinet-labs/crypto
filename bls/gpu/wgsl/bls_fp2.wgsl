// WGSL peer of bls_fp2.metal. Fp2 represented as 24 x u32 (c0 in [0..12), c1 in [12..24)).
// Byte layout matches blst_fp2: 96 bytes.

fn fp2_get_c0(a: array<u32, 24>) -> array<u32, 12> {
    var r: array<u32, 12>;
    for (var i = 0u; i < 12u; i = i + 1u) { r[i] = a[i]; }
    return r;
}
fn fp2_get_c1(a: array<u32, 24>) -> array<u32, 12> {
    var r: array<u32, 12>;
    for (var i = 0u; i < 12u; i = i + 1u) { r[i] = a[12u + i]; }
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
fn fp2_is_zero(a: array<u32, 24>) -> bool {
    var acc = 0u;
    for (var i = 0u; i < 24u; i = i + 1u) { acc = acc | a[i]; }
    return acc == 0u;
}

fn fp2_add(a: array<u32, 24>, b: array<u32, 24>) -> array<u32, 24> {
    let c0 = fp_add(fp2_get_c0(a), fp2_get_c0(b));
    let c1 = fp_add(fp2_get_c1(a), fp2_get_c1(b));
    return fp2_pack(c0, c1);
}
fn fp2_sub(a: array<u32, 24>, b: array<u32, 24>) -> array<u32, 24> {
    let c0 = fp_sub(fp2_get_c0(a), fp2_get_c0(b));
    let c1 = fp_sub(fp2_get_c1(a), fp2_get_c1(b));
    return fp2_pack(c0, c1);
}
fn fp2_neg(a: array<u32, 24>) -> array<u32, 24> {
    let c0 = fp_neg(fp2_get_c0(a));
    let c1 = fp_neg(fp2_get_c1(a));
    return fp2_pack(c0, c1);
}
fn fp2_mul(a: array<u32, 24>, b: array<u32, 24>) -> array<u32, 24> {
    let a0 = fp2_get_c0(a);
    let a1 = fp2_get_c1(a);
    let b0 = fp2_get_c0(b);
    let b1 = fp2_get_c1(b);
    let aa = fp_mul(a0, b0);
    let bb = fp_mul(a1, b1);
    let sa = fp_add(a0, a1);
    let sb = fp_add(b0, b1);
    let cross = fp_mul(sa, sb);
    let r0 = fp_sub(aa, bb);
    let r1 = fp_sub(fp_sub(cross, aa), bb);
    return fp2_pack(r0, r1);
}
fn fp2_sqr(a: array<u32, 24>) -> array<u32, 24> {
    let a0 = fp2_get_c0(a);
    let a1 = fp2_get_c1(a);
    let ab  = fp_mul(a0, a1);
    let sum = fp_add(a0, a1);
    let dif = fp_sub(a0, a1);
    let r0 = fp_mul(sum, dif);
    let r1 = fp_add(ab, ab);
    return fp2_pack(r0, r1);
}
fn fp2_conj(a: array<u32, 24>) -> array<u32, 24> {
    let c0 = fp2_get_c0(a);
    let c1 = fp_neg(fp2_get_c1(a));
    return fp2_pack(c0, c1);
}
fn fp2_inv(a: array<u32, 24>) -> array<u32, 24> {
    let a0 = fp2_get_c0(a);
    let a1 = fp2_get_c1(a);
    let t0 = fp_sqr(a0);
    let t1 = fp_sqr(a1);
    let norm = fp_add(t0, t1);
    let ni = fp_inv(norm);
    let r0 = fp_mul(a0, ni);
    let r1 = fp_neg(fp_mul(a1, ni));
    return fp2_pack(r0, r1);
}
fn fp2_frobenius(a: array<u32, 24>, n: u32) -> array<u32, 24> {
    if ((n & 1u) == 1u) { return fp2_conj(a); }
    return a;
}
fn fp2_mul_by_1_plus_u(a: array<u32, 24>) -> array<u32, 24> {
    let a0 = fp2_get_c0(a);
    let a1 = fp2_get_c1(a);
    let r0 = fp_sub(a0, a1);
    let r1 = fp_add(a0, a1);
    return fp2_pack(r0, r1);
}

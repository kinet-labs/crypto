// WGSL peer of bls_fp6.metal. Fp6 = 72 x u32 = 3 * Fp2  (288 bytes byte-equal blst_fp6).

fn fp6_get_c0(a: array<u32, 72>) -> array<u32, 24> {
    var r: array<u32, 24>;
    for (var i = 0u; i < 24u; i = i + 1u) { r[i] = a[i]; }
    return r;
}
fn fp6_get_c1(a: array<u32, 72>) -> array<u32, 24> {
    var r: array<u32, 24>;
    for (var i = 0u; i < 24u; i = i + 1u) { r[i] = a[24u + i]; }
    return r;
}
fn fp6_get_c2(a: array<u32, 72>) -> array<u32, 24> {
    var r: array<u32, 24>;
    for (var i = 0u; i < 24u; i = i + 1u) { r[i] = a[48u + i]; }
    return r;
}
fn fp6_pack(c0: array<u32, 24>, c1: array<u32, 24>, c2: array<u32, 24>) -> array<u32, 72> {
    var r: array<u32, 72>;
    for (var i = 0u; i < 24u; i = i + 1u) {
        r[i]        = c0[i];
        r[24u + i]  = c1[i];
        r[48u + i]  = c2[i];
    }
    return r;
}

fn fp6_add(a: array<u32, 72>, b: array<u32, 72>) -> array<u32, 72> {
    let r0 = fp2_add(fp6_get_c0(a), fp6_get_c0(b));
    let r1 = fp2_add(fp6_get_c1(a), fp6_get_c1(b));
    let r2 = fp2_add(fp6_get_c2(a), fp6_get_c2(b));
    return fp6_pack(r0, r1, r2);
}
fn fp6_sub(a: array<u32, 72>, b: array<u32, 72>) -> array<u32, 72> {
    let r0 = fp2_sub(fp6_get_c0(a), fp6_get_c0(b));
    let r1 = fp2_sub(fp6_get_c1(a), fp6_get_c1(b));
    let r2 = fp2_sub(fp6_get_c2(a), fp6_get_c2(b));
    return fp6_pack(r0, r1, r2);
}
fn fp6_neg(a: array<u32, 72>) -> array<u32, 72> {
    let r0 = fp2_neg(fp6_get_c0(a));
    let r1 = fp2_neg(fp6_get_c1(a));
    let r2 = fp2_neg(fp6_get_c2(a));
    return fp6_pack(r0, r1, r2);
}

fn fp6_mul(a: array<u32, 72>, b: array<u32, 72>) -> array<u32, 72> {
    let a0 = fp6_get_c0(a); let a1 = fp6_get_c1(a); let a2 = fp6_get_c2(a);
    let b0 = fp6_get_c0(b); let b1 = fp6_get_c1(b); let b2 = fp6_get_c2(b);

    let t0 = fp2_mul(a0, b0);
    let t1 = fp2_mul(a1, b1);
    let t2 = fp2_mul(a2, b2);

    var r0 = fp2_mul(fp2_add(a1, a2), fp2_add(b1, b2));
    r0 = fp2_sub(r0, t1);
    r0 = fp2_sub(r0, t2);
    r0 = fp2_mul_by_1_plus_u(r0);
    r0 = fp2_add(r0, t0);

    var r1 = fp2_mul(fp2_add(a0, a1), fp2_add(b0, b1));
    r1 = fp2_sub(r1, t0);
    r1 = fp2_sub(r1, t1);
    r1 = fp2_add(r1, fp2_mul_by_1_plus_u(t2));

    var r2 = fp2_mul(fp2_add(a0, a2), fp2_add(b0, b2));
    r2 = fp2_sub(r2, t0);
    r2 = fp2_sub(r2, t2);
    r2 = fp2_add(r2, t1);

    return fp6_pack(r0, r1, r2);
}

fn fp6_sqr(a: array<u32, 72>) -> array<u32, 72> {
    let a0 = fp6_get_c0(a); let a1 = fp6_get_c1(a); let a2 = fp6_get_c2(a);
    let s0  = fp2_sqr(a0);
    var m01 = fp2_mul(a0, a1); m01 = fp2_add(m01, m01);
    var m12 = fp2_mul(a1, a2); m12 = fp2_add(m12, m12);
    let s2  = fp2_sqr(a2);

    var r2 = fp2_sqr(fp2_add(fp2_add(a0, a1), a2));
    r2 = fp2_sub(r2, s0);
    r2 = fp2_sub(r2, s2);
    r2 = fp2_sub(r2, m01);
    r2 = fp2_sub(r2, m12);

    var r0 = fp2_mul_by_1_plus_u(m12);
    r0 = fp2_add(r0, s0);

    var r1 = fp2_mul_by_1_plus_u(s2);
    r1 = fp2_add(r1, m01);

    return fp6_pack(r0, r1, r2);
}

fn fp6_inv(a: array<u32, 72>) -> array<u32, 72> {
    let a0 = fp6_get_c0(a); let a1 = fp6_get_c1(a); let a2 = fp6_get_c2(a);
    var c0 = fp2_sqr(a0);
    var t  = fp2_mul(a1, a2);
    t = fp2_mul_by_1_plus_u(t);
    c0 = fp2_sub(c0, t);

    var c1 = fp2_sqr(a2);
    c1 = fp2_mul_by_1_plus_u(c1);
    let t01 = fp2_mul(a0, a1);
    c1 = fp2_sub(c1, t01);

    var c2 = fp2_sqr(a1);
    let t02 = fp2_mul(a0, a2);
    c2 = fp2_sub(c2, t02);

    let n1 = fp2_mul(c1, a2);
    let n2 = fp2_mul(c2, a1);
    var norm = fp2_add(n1, n2);
    norm = fp2_mul_by_1_plus_u(norm);
    norm = fp2_add(norm, fp2_mul(c0, a0));

    let ni = fp2_inv(norm);

    let r0 = fp2_mul(c0, ni);
    let r1 = fp2_mul(c1, ni);
    let r2 = fp2_mul(c2, ni);
    return fp6_pack(r0, r1, r2);
}

// Frobenius coefficient tables (in Montgomery form). These are 12 x u32 LE
// renderings of the same constants used in bls_fp6.metal. Built as helpers.
fn frob6_c1_n1() -> array<u32, 24> {
    // (real=0, imag=hex sequence from Metal FP6_FROB_C1_IM_N1)
    var c0: array<u32, 12>; for (var i = 0u; i < 12u; i = i + 1u) { c0[i] = 0u; }
    let c1 = array<u32, 12>(
        0x8671F071u, 0xCD03C9E4u, 0x1FCDA5D2u, 0x5DAB2246u,
        0xD3851B95u, 0x587042AFu, 0x01BACB9Eu, 0x8EB60EBEu,
        0x83D050D2u, 0x03F97D6Eu, 0x54638741u, 0x18F02065u);
    return fp2_pack(c0, c1);
}
fn frob6_c1_n2() -> array<u32, 24> {
    let c0 = array<u32, 12>(
        0x798A64E8u, 0x30F1361Bu, 0x7ECE5A2Au, 0xF3B8DDABu,
        0xC61577F7u, 0x16A8CA3Au, 0x74FD029Bu, 0xC26A2FF8u,
        0x60701C6Eu, 0x3636B766u, 0x241B6160u, 0x051BA4ABu);
    var c1: array<u32, 12>; for (var i = 0u; i < 12u; i = i + 1u) { c1[i] = 0u; }
    return fp2_pack(c0, c1);
}
fn frob6_c1_n3() -> array<u32, 24> {
    var c0: array<u32, 12>; for (var i = 0u; i < 12u; i = i + 1u) { c0[i] = 0u; }
    let c1 = array<u32, 12>(
        0x0002FFFDu, 0x76090000u, 0xC40C0002u, 0xEBF40000u,
        0x53C758BAu, 0x5F489857u, 0x70525745u, 0x77CE5853u,
        0xA256EC6Du, 0x5C071A97u, 0xFA80E493u, 0x15F65EC3u);
    return fp2_pack(c0, c1);
}
fn frob6_c2_n1() -> array<u32, 12> {
    return array<u32, 12>(
        0x867545C3u, 0x890DC9E4u, 0x3285A5D5u, 0x2AF32253u,
        0x309B7E2Cu, 0x50880866u, 0x7E881024u, 0xA20D1B8Cu,
        0xE2DB9068u, 0x14E4F04Fu, 0x1564853Au, 0x14E56D3Fu);
}
fn frob6_c2_n2() -> array<u32, 12> {
    return array<u32, 12>(
        0x8671F071u, 0xCD03C9E4u, 0x1FCDA5D2u, 0x5DAB2246u,
        0xD3851B95u, 0x587042AFu, 0x01BACB9Eu, 0x8EB60EBEu,
        0x83D050D2u, 0x03F97D6Eu, 0x54638741u, 0x18F02065u);
}
fn frob6_c2_n3() -> array<u32, 12> {
    return array<u32, 12>(
        0xFFFCAAAEu, 0x43F5FFFFu, 0xED47FFFDu, 0x32B7FFF2u,
        0xA2E99D69u, 0x07E83A49u, 0x8332BB7Au, 0xECA8F331u,
        0xA0F4C069u, 0xEF148D1Eu, 0x3EFF0206u, 0x040AB326u);
}

fn fp6_frobenius(a: array<u32, 72>, n: u32) -> array<u32, 72> {
    var r0 = fp2_frobenius(fp6_get_c0(a), n);
    var r1 = fp2_frobenius(fp6_get_c1(a), n);
    var r2 = fp2_frobenius(fp6_get_c2(a), n);

    var c1: array<u32, 24>;
    var c2_real: array<u32, 12>;
    if (n == 1u) { c1 = frob6_c1_n1(); c2_real = frob6_c2_n1(); }
    else if (n == 2u) { c1 = frob6_c1_n2(); c2_real = frob6_c2_n2(); }
    else { c1 = frob6_c1_n3(); c2_real = frob6_c2_n3(); }

    r1 = fp2_mul(r1, c1);
    let r2_c0 = fp_mul(fp2_get_c0(r2), c2_real);
    let r2_c1 = fp_mul(fp2_get_c1(r2), c2_real);
    r2 = fp2_pack(r2_c0, r2_c1);

    return fp6_pack(r0, r1, r2);
}

// WGSL peer of bls_fp6.metal. Fp6 = 72 x u32 = 3 * Fp2  (288 bytes byte-equal blst_fp6).
//
// Out-pointer form for every function used by the Fp12 call tree.
// Returning array<u32, 72> by value materialises a stack copy at every call
// site; the karatsuba/inversion call tree on the upper tower then exceeds
// AGXMetalG13X's function-call stack budget. Out-pointer form keeps every
// intermediate in a single named slot the caller already owns. Same
// arithmetic as Metal.
//
// Intermediates are computed into local Fp2 scratches (24 x u32) instead of
// chains of `let r = fp2_*(...)` which each materialise a 96-byte copy.

fn fp6_get_c0(a: ptr<function, array<u32, 72>>, out: ptr<function, array<u32, 24>>) {
    for (var i = 0u; i < 24u; i = i + 1u) { (*out)[i] = (*a)[i]; }
}
fn fp6_get_c1(a: ptr<function, array<u32, 72>>, out: ptr<function, array<u32, 24>>) {
    for (var i = 0u; i < 24u; i = i + 1u) { (*out)[i] = (*a)[24u + i]; }
}
fn fp6_get_c2(a: ptr<function, array<u32, 72>>, out: ptr<function, array<u32, 24>>) {
    for (var i = 0u; i < 24u; i = i + 1u) { (*out)[i] = (*a)[48u + i]; }
}
fn fp6_set_c0(out: ptr<function, array<u32, 72>>, v: ptr<function, array<u32, 24>>) {
    for (var i = 0u; i < 24u; i = i + 1u) { (*out)[i] = (*v)[i]; }
}
fn fp6_set_c1(out: ptr<function, array<u32, 72>>, v: ptr<function, array<u32, 24>>) {
    for (var i = 0u; i < 24u; i = i + 1u) { (*out)[24u + i] = (*v)[i]; }
}
fn fp6_set_c2(out: ptr<function, array<u32, 72>>, v: ptr<function, array<u32, 24>>) {
    for (var i = 0u; i < 24u; i = i + 1u) { (*out)[48u + i] = (*v)[i]; }
}

// ---------- Out-pointer Fp6 primitives ----------

fn fp6_add_p(a: ptr<function, array<u32, 72>>, b: ptr<function, array<u32, 72>>,
             out: ptr<function, array<u32, 72>>) {
    var a0: array<u32, 24>; fp6_get_c0(a, &a0);
    var a1: array<u32, 24>; fp6_get_c1(a, &a1);
    var a2: array<u32, 24>; fp6_get_c2(a, &a2);
    var b0: array<u32, 24>; fp6_get_c0(b, &b0);
    var b1: array<u32, 24>; fp6_get_c1(b, &b1);
    var b2: array<u32, 24>; fp6_get_c2(b, &b2);
    var r: array<u32, 24>;
    fp2_add_p(&a0, &b0, &r); fp6_set_c0(out, &r);
    fp2_add_p(&a1, &b1, &r); fp6_set_c1(out, &r);
    fp2_add_p(&a2, &b2, &r); fp6_set_c2(out, &r);
}
fn fp6_sub_p(a: ptr<function, array<u32, 72>>, b: ptr<function, array<u32, 72>>,
             out: ptr<function, array<u32, 72>>) {
    var a0: array<u32, 24>; fp6_get_c0(a, &a0);
    var a1: array<u32, 24>; fp6_get_c1(a, &a1);
    var a2: array<u32, 24>; fp6_get_c2(a, &a2);
    var b0: array<u32, 24>; fp6_get_c0(b, &b0);
    var b1: array<u32, 24>; fp6_get_c1(b, &b1);
    var b2: array<u32, 24>; fp6_get_c2(b, &b2);
    var r: array<u32, 24>;
    fp2_sub_p(&a0, &b0, &r); fp6_set_c0(out, &r);
    fp2_sub_p(&a1, &b1, &r); fp6_set_c1(out, &r);
    fp2_sub_p(&a2, &b2, &r); fp6_set_c2(out, &r);
}
fn fp6_neg_p(a: ptr<function, array<u32, 72>>, out: ptr<function, array<u32, 72>>) {
    var a0: array<u32, 24>; fp6_get_c0(a, &a0);
    var a1: array<u32, 24>; fp6_get_c1(a, &a1);
    var a2: array<u32, 24>; fp6_get_c2(a, &a2);
    var r: array<u32, 24>;
    fp2_neg_p(&a0, &r); fp6_set_c0(out, &r);
    fp2_neg_p(&a1, &r); fp6_set_c1(out, &r);
    fp2_neg_p(&a2, &r); fp6_set_c2(out, &r);
}

fn fp6_mul_p(a: ptr<function, array<u32, 72>>, b: ptr<function, array<u32, 72>>,
             out: ptr<function, array<u32, 72>>) {
    var a0: array<u32, 24>; fp6_get_c0(a, &a0);
    var a1: array<u32, 24>; fp6_get_c1(a, &a1);
    var a2: array<u32, 24>; fp6_get_c2(a, &a2);
    var b0: array<u32, 24>; fp6_get_c0(b, &b0);
    var b1: array<u32, 24>; fp6_get_c1(b, &b1);
    var b2: array<u32, 24>; fp6_get_c2(b, &b2);

    var t0: array<u32, 24>; fp2_mul_p(&a0, &b0, &t0);
    var t1: array<u32, 24>; fp2_mul_p(&a1, &b1, &t1);
    var t2: array<u32, 24>; fp2_mul_p(&a2, &b2, &t2);

    var s_a: array<u32, 24>;
    var s_b: array<u32, 24>;
    var tmp: array<u32, 24>;
    var r0: array<u32, 24>;
    var r1: array<u32, 24>;
    var r2: array<u32, 24>;

    // r0 = ((a1+a2)(b1+b2) - t1 - t2)(u+1) + t0
    fp2_add_p(&a1, &a2, &s_a);
    fp2_add_p(&b1, &b2, &s_b);
    fp2_mul_p(&s_a, &s_b, &tmp);
    fp2_sub_p(&tmp, &t1, &tmp);
    fp2_sub_p(&tmp, &t2, &tmp);
    fp2_mul_by_1_plus_u_p(&tmp, &tmp);
    fp2_add_p(&tmp, &t0, &r0);

    // r1 = (a0+a1)(b0+b1) - t0 - t1 + t2(u+1)
    fp2_add_p(&a0, &a1, &s_a);
    fp2_add_p(&b0, &b1, &s_b);
    fp2_mul_p(&s_a, &s_b, &tmp);
    fp2_sub_p(&tmp, &t0, &tmp);
    fp2_sub_p(&tmp, &t1, &tmp);
    var t2_v: array<u32, 24>; fp2_mul_by_1_plus_u_p(&t2, &t2_v);
    fp2_add_p(&tmp, &t2_v, &r1);

    // r2 = (a0+a2)(b0+b2) - t0 - t2 + t1
    fp2_add_p(&a0, &a2, &s_a);
    fp2_add_p(&b0, &b2, &s_b);
    fp2_mul_p(&s_a, &s_b, &tmp);
    fp2_sub_p(&tmp, &t0, &tmp);
    fp2_sub_p(&tmp, &t2, &tmp);
    fp2_add_p(&tmp, &t1, &r2);

    fp6_set_c0(out, &r0);
    fp6_set_c1(out, &r1);
    fp6_set_c2(out, &r2);
}

fn fp6_sqr_p(a: ptr<function, array<u32, 72>>, out: ptr<function, array<u32, 72>>) {
    var a0: array<u32, 24>; fp6_get_c0(a, &a0);
    var a1: array<u32, 24>; fp6_get_c1(a, &a1);
    var a2: array<u32, 24>; fp6_get_c2(a, &a2);

    var s0: array<u32, 24>;  fp2_sqr_p(&a0, &s0);
    var s2: array<u32, 24>;  fp2_sqr_p(&a2, &s2);
    var m01: array<u32, 24>; fp2_mul_p(&a0, &a1, &m01); fp2_add_p(&m01, &m01, &m01);
    var m12: array<u32, 24>; fp2_mul_p(&a1, &a2, &m12); fp2_add_p(&m12, &m12, &m12);

    var r2: array<u32, 24>;
    var sum: array<u32, 24>;
    fp2_add_p(&a0, &a1, &sum);
    fp2_add_p(&sum, &a2, &sum);
    fp2_sqr_p(&sum, &r2);
    fp2_sub_p(&r2, &s0, &r2);
    fp2_sub_p(&r2, &s2, &r2);
    fp2_sub_p(&r2, &m01, &r2);
    fp2_sub_p(&r2, &m12, &r2);

    var r0: array<u32, 24>;
    fp2_mul_by_1_plus_u_p(&m12, &r0);
    fp2_add_p(&r0, &s0, &r0);

    var r1: array<u32, 24>;
    fp2_mul_by_1_plus_u_p(&s2, &r1);
    fp2_add_p(&r1, &m01, &r1);

    fp6_set_c0(out, &r0);
    fp6_set_c1(out, &r1);
    fp6_set_c2(out, &r2);
}

fn fp6_inv_p(a: ptr<function, array<u32, 72>>, out: ptr<function, array<u32, 72>>) {
    var a0: array<u32, 24>; fp6_get_c0(a, &a0);
    var a1: array<u32, 24>; fp6_get_c1(a, &a1);
    var a2: array<u32, 24>; fp6_get_c2(a, &a2);

    // c0 = a0^2 - mul_v(a1*a2)
    var c0: array<u32, 24>;
    var tmp: array<u32, 24>;
    fp2_sqr_p(&a0, &c0);
    fp2_mul_p(&a1, &a2, &tmp);
    fp2_mul_by_1_plus_u_p(&tmp, &tmp);
    fp2_sub_p(&c0, &tmp, &c0);

    // c1 = mul_v(a2^2) - a0*a1
    var c1: array<u32, 24>;
    fp2_sqr_p(&a2, &c1);
    fp2_mul_by_1_plus_u_p(&c1, &c1);
    fp2_mul_p(&a0, &a1, &tmp);
    fp2_sub_p(&c1, &tmp, &c1);

    // c2 = a1^2 - a0*a2
    var c2: array<u32, 24>;
    fp2_sqr_p(&a1, &c2);
    fp2_mul_p(&a0, &a2, &tmp);
    fp2_sub_p(&c2, &tmp, &c2);

    // norm = mul_v(a2*c1 + a1*c2) + a0*c0
    var norm: array<u32, 24>;
    var t1: array<u32, 24>;
    fp2_mul_p(&c1, &a2, &t1);
    fp2_mul_p(&c2, &a1, &tmp);
    fp2_add_p(&t1, &tmp, &norm);
    fp2_mul_by_1_plus_u_p(&norm, &norm);
    fp2_mul_p(&c0, &a0, &tmp);
    fp2_add_p(&norm, &tmp, &norm);

    var ni: array<u32, 24>;
    fp2_inv_p(&norm, &ni);

    var r: array<u32, 24>;
    fp2_mul_p(&c0, &ni, &r); fp6_set_c0(out, &r);
    fp2_mul_p(&c1, &ni, &r); fp6_set_c1(out, &r);
    fp2_mul_p(&c2, &ni, &r); fp6_set_c2(out, &r);
}

// Frobenius coefficient tables (in Montgomery form). 12 x u32 LE renderings of
// the same constants used in bls_fp6.metal.
fn frob6_c1_n1(out: ptr<function, array<u32, 24>>) {
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = 0u; }
    (*out)[12u + 0u] = 0x8671F071u; (*out)[12u + 1u] = 0xCD03C9E4u;
    (*out)[12u + 2u] = 0x1FCDA5D2u; (*out)[12u + 3u] = 0x5DAB2246u;
    (*out)[12u + 4u] = 0xD3851B95u; (*out)[12u + 5u] = 0x587042AFu;
    (*out)[12u + 6u] = 0x01BACB9Eu; (*out)[12u + 7u] = 0x8EB60EBEu;
    (*out)[12u + 8u] = 0x83D050D2u; (*out)[12u + 9u] = 0x03F97D6Eu;
    (*out)[12u + 10u] = 0x54638741u; (*out)[12u + 11u] = 0x18F02065u;
}
fn frob6_c1_n2(out: ptr<function, array<u32, 24>>) {
    (*out)[0u] = 0x798A64E8u; (*out)[1u] = 0x30F1361Bu;
    (*out)[2u] = 0x7ECE5A2Au; (*out)[3u] = 0xF3B8DDABu;
    (*out)[4u] = 0xC61577F7u; (*out)[5u] = 0x16A8CA3Au;
    (*out)[6u] = 0x74FD029Bu; (*out)[7u] = 0xC26A2FF8u;
    (*out)[8u] = 0x60701C6Eu; (*out)[9u] = 0x3636B766u;
    (*out)[10u] = 0x241B6160u; (*out)[11u] = 0x051BA4ABu;
    for (var i = 12u; i < 24u; i = i + 1u) { (*out)[i] = 0u; }
}
fn frob6_c1_n3(out: ptr<function, array<u32, 24>>) {
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = 0u; }
    (*out)[12u + 0u] = 0x0002FFFDu; (*out)[12u + 1u] = 0x76090000u;
    (*out)[12u + 2u] = 0xC40C0002u; (*out)[12u + 3u] = 0xEBF40000u;
    (*out)[12u + 4u] = 0x53C758BAu; (*out)[12u + 5u] = 0x5F489857u;
    (*out)[12u + 6u] = 0x70525745u; (*out)[12u + 7u] = 0x77CE5853u;
    (*out)[12u + 8u] = 0xA256EC6Du; (*out)[12u + 9u] = 0x5C071A97u;
    (*out)[12u + 10u] = 0xFA80E493u; (*out)[12u + 11u] = 0x15F65EC3u;
}
fn frob6_c2_n1(out: ptr<function, array<u32, 12>>) {
    (*out)[0u] = 0x867545C3u; (*out)[1u] = 0x890DC9E4u;
    (*out)[2u] = 0x3285A5D5u; (*out)[3u] = 0x2AF32253u;
    (*out)[4u] = 0x309B7E2Cu; (*out)[5u] = 0x50880866u;
    (*out)[6u] = 0x7E881024u; (*out)[7u] = 0xA20D1B8Cu;
    (*out)[8u] = 0xE2DB9068u; (*out)[9u] = 0x14E4F04Fu;
    (*out)[10u] = 0x1564853Au; (*out)[11u] = 0x14E56D3Fu;
}
fn frob6_c2_n2(out: ptr<function, array<u32, 12>>) {
    (*out)[0u] = 0x8671F071u; (*out)[1u] = 0xCD03C9E4u;
    (*out)[2u] = 0x1FCDA5D2u; (*out)[3u] = 0x5DAB2246u;
    (*out)[4u] = 0xD3851B95u; (*out)[5u] = 0x587042AFu;
    (*out)[6u] = 0x01BACB9Eu; (*out)[7u] = 0x8EB60EBEu;
    (*out)[8u] = 0x83D050D2u; (*out)[9u] = 0x03F97D6Eu;
    (*out)[10u] = 0x54638741u; (*out)[11u] = 0x18F02065u;
}
fn frob6_c2_n3(out: ptr<function, array<u32, 12>>) {
    (*out)[0u] = 0xFFFCAAAEu; (*out)[1u] = 0x43F5FFFFu;
    (*out)[2u] = 0xED47FFFDu; (*out)[3u] = 0x32B7FFF2u;
    (*out)[4u] = 0xA2E99D69u; (*out)[5u] = 0x07E83A49u;
    (*out)[6u] = 0x8332BB7Au; (*out)[7u] = 0xECA8F331u;
    (*out)[8u] = 0xA0F4C069u; (*out)[9u] = 0xEF148D1Eu;
    (*out)[10u] = 0x3EFF0206u; (*out)[11u] = 0x040AB326u;
}

fn fp6_frobenius_p(a: ptr<function, array<u32, 72>>, n: u32,
                   out: ptr<function, array<u32, 72>>) {
    var a0: array<u32, 24>; fp6_get_c0(a, &a0);
    var a1: array<u32, 24>; fp6_get_c1(a, &a1);
    var a2: array<u32, 24>; fp6_get_c2(a, &a2);
    var r0: array<u32, 24>; fp2_frobenius_p(&a0, n, &r0);
    var r1: array<u32, 24>; fp2_frobenius_p(&a1, n, &r1);
    var r2: array<u32, 24>; fp2_frobenius_p(&a2, n, &r2);

    var c1: array<u32, 24>;
    var c2_real: array<u32, 12>;
    if (n == 1u) { frob6_c1_n1(&c1); frob6_c2_n1(&c2_real); }
    else if (n == 2u) { frob6_c1_n2(&c1); frob6_c2_n2(&c2_real); }
    else { frob6_c1_n3(&c1); frob6_c2_n3(&c2_real); }

    var r1_new: array<u32, 24>; fp2_mul_p(&r1, &c1, &r1_new);
    var r2_c0_in = fp2_get_c0(&r2);
    var r2_c1_in = fp2_get_c1(&r2);
    let r2_c0 = fp_mul(r2_c0_in, c2_real);
    let r2_c1 = fp_mul(r2_c1_in, c2_real);
    var r2_new: array<u32, 24>;
    for (var i = 0u; i < 12u; i = i + 1u) { r2_new[i] = r2_c0[i]; r2_new[12u + i] = r2_c1[i]; }

    fp6_set_c0(out, &r0);
    fp6_set_c1(out, &r1_new);
    fp6_set_c2(out, &r2_new);
}

// (a0 + a1 v + a2 v^2) * v = a2 (u+1) + a0 v + a1 v^2  (Fp6 in Fp2 layout)
fn fp6_mul_by_v_p(a: ptr<function, array<u32, 72>>,
                  out: ptr<function, array<u32, 72>>) {
    var a2: array<u32, 24>; fp6_get_c2(a, &a2);
    var r0: array<u32, 24>; fp2_mul_by_1_plus_u_p(&a2, &r0);
    var r1: array<u32, 24>; fp6_get_c0(a, &r1);
    var r2: array<u32, 24>; fp6_get_c1(a, &r2);
    fp6_set_c0(out, &r0);
    fp6_set_c1(out, &r1);
    fp6_set_c2(out, &r2);
}

// ---------- Legacy by-value Fp6 (Stage-1 kernels keep this) ----------

fn fp6_pack_v(c0: array<u32, 24>, c1: array<u32, 24>, c2: array<u32, 24>) -> array<u32, 72> {
    var r: array<u32, 72>;
    for (var i = 0u; i < 24u; i = i + 1u) {
        r[i]        = c0[i];
        r[24u + i]  = c1[i];
        r[48u + i]  = c2[i];
    }
    return r;
}

fn fp6_add(a: ptr<function, array<u32, 72>>, b: ptr<function, array<u32, 72>>) -> array<u32, 72> {
    var r: array<u32, 72>;
    fp6_add_p(a, b, &r);
    return r;
}
fn fp6_sub(a: ptr<function, array<u32, 72>>, b: ptr<function, array<u32, 72>>) -> array<u32, 72> {
    var r: array<u32, 72>;
    fp6_sub_p(a, b, &r);
    return r;
}
fn fp6_neg(a: ptr<function, array<u32, 72>>) -> array<u32, 72> {
    var r: array<u32, 72>;
    fp6_neg_p(a, &r);
    return r;
}
fn fp6_mul(a: ptr<function, array<u32, 72>>, b: ptr<function, array<u32, 72>>) -> array<u32, 72> {
    var r: array<u32, 72>;
    fp6_mul_p(a, b, &r);
    return r;
}
fn fp6_sqr(a: ptr<function, array<u32, 72>>) -> array<u32, 72> {
    var r: array<u32, 72>;
    fp6_sqr_p(a, &r);
    return r;
}
fn fp6_inv(a: ptr<function, array<u32, 72>>) -> array<u32, 72> {
    var r: array<u32, 72>;
    fp6_inv_p(a, &r);
    return r;
}
fn fp6_frobenius(a: ptr<function, array<u32, 72>>, n: u32) -> array<u32, 72> {
    var r: array<u32, 72>;
    fp6_frobenius_p(a, n, &r);
    return r;
}

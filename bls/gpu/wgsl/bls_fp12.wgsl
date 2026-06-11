// WGSL peer of bls_fp12.metal. Fp12 = 144 x u32 = 2 * Fp6 (576 bytes byte-equal blst_fp12).
//
// Out-pointer form for every function. Returning array<u32, 144> by value
// materialises a stack copy at every call site and the karatsuba/inversion
// call tree (fp6_inv inside fp12_inv etc.) blows AGXMetalG13X's function-call
// stack budget. Out-pointer form keeps every intermediate in a single named
// slot the caller already owns. Same arithmetic as Metal.

fn fp12_get_c0(a: ptr<function, array<u32, 144>>, out: ptr<function, array<u32, 72>>) {
    for (var i = 0u; i < 72u; i = i + 1u) { (*out)[i] = (*a)[i]; }
}
fn fp12_get_c1(a: ptr<function, array<u32, 144>>, out: ptr<function, array<u32, 72>>) {
    for (var i = 0u; i < 72u; i = i + 1u) { (*out)[i] = (*a)[72u + i]; }
}
fn fp12_set_c0(out: ptr<function, array<u32, 144>>, v: ptr<function, array<u32, 72>>) {
    for (var i = 0u; i < 72u; i = i + 1u) { (*out)[i] = (*v)[i]; }
}
fn fp12_set_c1(out: ptr<function, array<u32, 144>>, v: ptr<function, array<u32, 72>>) {
    for (var i = 0u; i < 72u; i = i + 1u) { (*out)[72u + i] = (*v)[i]; }
}

// ---------- Out-pointer Fp12 primitives ----------

fn fp12_add_p(a: ptr<function, array<u32, 144>>, b: ptr<function, array<u32, 144>>,
              out: ptr<function, array<u32, 144>>) {
    var a0: array<u32, 72>; fp12_get_c0(a, &a0);
    var a1: array<u32, 72>; fp12_get_c1(a, &a1);
    var b0: array<u32, 72>; fp12_get_c0(b, &b0);
    var b1: array<u32, 72>; fp12_get_c1(b, &b1);
    var r: array<u32, 72>;
    fp6_add_p(&a0, &b0, &r); fp12_set_c0(out, &r);
    fp6_add_p(&a1, &b1, &r); fp12_set_c1(out, &r);
}
fn fp12_sub_p(a: ptr<function, array<u32, 144>>, b: ptr<function, array<u32, 144>>,
              out: ptr<function, array<u32, 144>>) {
    var a0: array<u32, 72>; fp12_get_c0(a, &a0);
    var a1: array<u32, 72>; fp12_get_c1(a, &a1);
    var b0: array<u32, 72>; fp12_get_c0(b, &b0);
    var b1: array<u32, 72>; fp12_get_c1(b, &b1);
    var r: array<u32, 72>;
    fp6_sub_p(&a0, &b0, &r); fp12_set_c0(out, &r);
    fp6_sub_p(&a1, &b1, &r); fp12_set_c1(out, &r);
}
fn fp12_conj_p(a: ptr<function, array<u32, 144>>, out: ptr<function, array<u32, 144>>) {
    var c0: array<u32, 72>; fp12_get_c0(a, &c0);
    var c1: array<u32, 72>; fp12_get_c1(a, &c1);
    var r1: array<u32, 72>; fp6_neg_p(&c1, &r1);
    fp12_set_c0(out, &c0);
    fp12_set_c1(out, &r1);
}

fn fp12_mul_p(a: ptr<function, array<u32, 144>>, b: ptr<function, array<u32, 144>>,
              out: ptr<function, array<u32, 144>>) {
    var a0: array<u32, 72>; fp12_get_c0(a, &a0);
    var a1: array<u32, 72>; fp12_get_c1(a, &a1);
    var b0: array<u32, 72>; fp12_get_c0(b, &b0);
    var b1: array<u32, 72>; fp12_get_c1(b, &b1);

    var t0: array<u32, 72>; fp6_mul_p(&a0, &b0, &t0);
    var t1: array<u32, 72>; fp6_mul_p(&a1, &b1, &t1);

    var sa: array<u32, 72>; fp6_add_p(&a0, &a1, &sa);
    var sb: array<u32, 72>; fp6_add_p(&b0, &b1, &sb);
    var prod: array<u32, 72>; fp6_mul_p(&sa, &sb, &prod);

    var r1_v: array<u32, 72>;
    fp6_sub_p(&prod, &t0, &r1_v);
    fp6_sub_p(&r1_v, &t1, &r1_v);

    var t1v: array<u32, 72>; fp6_mul_by_v_p(&t1, &t1v);
    var r0: array<u32, 72>; fp6_add_p(&t0, &t1v, &r0);

    fp12_set_c0(out, &r0);
    fp12_set_c1(out, &r1_v);
}

fn fp12_sqr_p(a: ptr<function, array<u32, 144>>, out: ptr<function, array<u32, 144>>) {
    var a0: array<u32, 72>; fp12_get_c0(a, &a0);
    var a1: array<u32, 72>; fp12_get_c1(a, &a1);

    var s: array<u32, 72>; fp6_add_p(&a0, &a1, &s);
    var t1v: array<u32, 72>; fp6_mul_by_v_p(&a1, &t1v);
    var t1: array<u32, 72>; fp6_add_p(&a0, &t1v, &t1);
    var t0: array<u32, 72>; fp6_mul_p(&s, &t1, &t0);

    var t2: array<u32, 72>; fp6_mul_p(&a0, &a1, &t2);
    var r1: array<u32, 72>; fp6_add_p(&t2, &t2, &r1);
    var r0: array<u32, 72>;
    fp6_sub_p(&t0, &t2, &r0);
    var t2v: array<u32, 72>; fp6_mul_by_v_p(&t2, &t2v);
    fp6_sub_p(&r0, &t2v, &r0);

    fp12_set_c0(out, &r0);
    fp12_set_c1(out, &r1);
}

fn fp12_inv_p(a: ptr<function, array<u32, 144>>, out: ptr<function, array<u32, 144>>) {
    var a0: array<u32, 72>; fp12_get_c0(a, &a0);
    var a1: array<u32, 72>; fp12_get_c1(a, &a1);

    var t0: array<u32, 72>; fp6_sqr_p(&a0, &t0);
    var t1: array<u32, 72>; fp6_sqr_p(&a1, &t1);
    var t1v: array<u32, 72>; fp6_mul_by_v_p(&t1, &t1v);
    var diff: array<u32, 72>; fp6_sub_p(&t0, &t1v, &diff);
    var ti: array<u32, 72>; fp6_inv_p(&diff, &ti);

    var r0: array<u32, 72>; fp6_mul_p(&a0, &ti, &r0);
    var r1_pos: array<u32, 72>; fp6_mul_p(&a1, &ti, &r1_pos);
    var r1: array<u32, 72>; fp6_neg_p(&r1_pos, &r1);

    fp12_set_c0(out, &r0);
    fp12_set_c1(out, &r1);
}

// Cyclotomic squaring in Fp12. Mirrors blst's cyclotomic_sqr_fp12 + sqr_fp4.
//
// sqr_fp4 produces (r0, r1) from (a0, a1) Fp2 pair; we write r0 / r1 through
// out-pointers so we don't materialise a 192-byte struct return.
fn sqr_fp4_p(a0: ptr<function, array<u32, 24>>,
             a1: ptr<function, array<u32, 24>>,
             r0: ptr<function, array<u32, 24>>,
             r1: ptr<function, array<u32, 24>>) {
    var t0: array<u32, 24>; fp2_sqr_p(a0, &t0);
    var t1: array<u32, 24>; fp2_sqr_p(a1, &t1);
    var sum: array<u32, 24>; fp2_add_p(a0, a1, &sum);

    var t1v: array<u32, 24>; fp2_mul_by_1_plus_u_p(&t1, &t1v);
    fp2_add_p(&t1v, &t0, r0);
    var sum_sq: array<u32, 24>; fp2_sqr_p(&sum, &sum_sq);
    fp2_sub_p(&sum_sq, &t0, r1);
    fp2_sub_p(r1, &t1, r1);
}

fn fp12_cyclotomic_sqr_p(a: ptr<function, array<u32, 144>>,
                         out: ptr<function, array<u32, 144>>) {
    var a_c0: array<u32, 72>; fp12_get_c0(a, &a_c0);
    var a_c1: array<u32, 72>; fp12_get_c1(a, &a_c1);
    var a00: array<u32, 24>; fp6_get_c0(&a_c0, &a00);
    var a01: array<u32, 24>; fp6_get_c1(&a_c0, &a01);
    var a02: array<u32, 24>; fp6_get_c2(&a_c0, &a02);
    var a10: array<u32, 24>; fp6_get_c0(&a_c1, &a10);
    var a11: array<u32, 24>; fp6_get_c1(&a_c1, &a11);
    var a12: array<u32, 24>; fp6_get_c2(&a_c1, &a12);

    var ta_r0: array<u32, 24>; var ta_r1: array<u32, 24>;
    sqr_fp4_p(&a00, &a11, &ta_r0, &ta_r1);
    var tb_r0: array<u32, 24>; var tb_r1: array<u32, 24>;
    sqr_fp4_p(&a10, &a02, &tb_r0, &tb_r1);
    var tc_r0: array<u32, 24>; var tc_r1: array<u32, 24>;
    sqr_fp4_p(&a01, &a12, &tc_r0, &tc_r1);

    // r.c0.c0 = 3 t00 - 2 a00
    var r00: array<u32, 24>;
    var tmp: array<u32, 24>;
    fp2_sub_p(&ta_r0, &a00, &tmp);
    fp2_add_p(&tmp, &tmp, &tmp);
    fp2_add_p(&tmp, &ta_r0, &r00);

    // r.c0.c1 = 3 t10 - 2 a01
    var r01: array<u32, 24>;
    fp2_sub_p(&tb_r0, &a01, &tmp);
    fp2_add_p(&tmp, &tmp, &tmp);
    fp2_add_p(&tmp, &tb_r0, &r01);

    // r.c0.c2 = 3 t20 - 2 a02
    var r02: array<u32, 24>;
    fp2_sub_p(&tc_r0, &a02, &tmp);
    fp2_add_p(&tmp, &tmp, &tmp);
    fp2_add_p(&tmp, &tc_r0, &r02);

    // r.c1.c0 = 3 (t21 * (u+1)) + 2 a10
    var r10: array<u32, 24>;
    var tcr1v: array<u32, 24>;
    fp2_mul_by_1_plus_u_p(&tc_r1, &tcr1v);
    fp2_add_p(&tcr1v, &a10, &tmp);
    fp2_add_p(&tmp, &tmp, &tmp);
    fp2_add_p(&tmp, &tcr1v, &r10);

    // r.c1.c1 = 3 t01 + 2 a11
    var r11: array<u32, 24>;
    fp2_add_p(&ta_r1, &a11, &tmp);
    fp2_add_p(&tmp, &tmp, &tmp);
    fp2_add_p(&tmp, &ta_r1, &r11);

    // r.c1.c2 = 3 t11 + 2 a12
    var r12: array<u32, 24>;
    fp2_add_p(&tb_r1, &a12, &tmp);
    fp2_add_p(&tmp, &tmp, &tmp);
    fp2_add_p(&tmp, &tb_r1, &r12);

    var c0: array<u32, 72>;
    fp6_set_c0(&c0, &r00);
    fp6_set_c1(&c0, &r01);
    fp6_set_c2(&c0, &r02);
    var c1: array<u32, 72>;
    fp6_set_c0(&c1, &r10);
    fp6_set_c1(&c1, &r11);
    fp6_set_c2(&c1, &r12);
    fp12_set_c0(out, &c0);
    fp12_set_c1(out, &c1);
}

// Frobenius for Fp12.
fn frob12_n1(out: ptr<function, array<u32, 24>>) {
    (*out)[0u] = 0xB319D465u; (*out)[1u] = 0x07089552u;
    (*out)[2u] = 0xB50A8313u; (*out)[3u] = 0xC6695F92u;
    (*out)[4u] = 0xD117228Fu; (*out)[5u] = 0x97E83CCCu;
    (*out)[6u] = 0xB2DC29EEu; (*out)[7u] = 0xA35BAECAu;
    (*out)[8u] = 0x5DAACE4Du; (*out)[9u] = 0x1CE393EAu;
    (*out)[10u] = 0xB0FB66EBu; (*out)[11u] = 0x08F2220Fu;
    (*out)[12u + 0u] = 0x4CE5D646u; (*out)[12u + 1u] = 0xB2F66AADu;
    (*out)[12u + 2u] = 0xFC497CECu; (*out)[12u + 3u] = 0x5842A06Bu;
    (*out)[12u + 4u] = 0x2599D394u; (*out)[12u + 5u] = 0xCF4895D4u;
    (*out)[12u + 6u] = 0x40A8E8D0u; (*out)[12u + 7u] = 0xC11B9CBAu;
    (*out)[12u + 8u] = 0xE5A0DE89u; (*out)[12u + 9u] = 0x2E3813CBu;
    (*out)[12u + 10u] = 0x88847FAFu; (*out)[12u + 11u] = 0x110EEFDAu;
}
fn frob12_n2(out: ptr<function, array<u32, 24>>) {
    (*out)[0u] = 0x798DBA3Au; (*out)[1u] = 0xECFB361Bu;
    (*out)[2u] = 0x91865A2Cu; (*out)[3u] = 0xC100DDB8u;
    (*out)[4u] = 0x232BDA8Eu; (*out)[5u] = 0x0EC08FF1u;
    (*out)[6u] = 0xF1CA4721u; (*out)[7u] = 0xD5C13CC6u;
    (*out)[8u] = 0xBF7B5C04u; (*out)[9u] = 0x47222A47u;
    (*out)[10u] = 0xE51C5F59u; (*out)[11u] = 0x0110F184u;
    for (var i = 12u; i < 24u; i = i + 1u) { (*out)[i] = 0u; }
}
fn frob12_n3(out: ptr<function, array<u32, 24>>) {
    (*out)[0u] = 0xA55C9AD1u; (*out)[1u] = 0x3E2F585Du;
    (*out)[2u] = 0x86C18183u; (*out)[3u] = 0x4294213Du;
    (*out)[4u] = 0x8B623732u; (*out)[5u] = 0x382844C8u;
    (*out)[6u] = 0x19103E18u; (*out)[7u] = 0x92AD2AFDu;
    (*out)[8u] = 0xAC7CF0B9u; (*out)[9u] = 0x1D794E4Fu;
    (*out)[10u] = 0x7D825EC8u; (*out)[11u] = 0x0BD592FCu;
    (*out)[12u + 0u] = 0x5AA30FDAu; (*out)[12u + 1u] = 0x7BCFA7A2u;
    (*out)[12u + 2u] = 0x2A927E7Cu; (*out)[12u + 3u] = 0xDC17DEC1u;
    (*out)[12u + 4u] = 0x6B4EBEF1u; (*out)[12u + 5u] = 0x2F088DD8u;
    (*out)[12u + 6u] = 0xDA74D4A7u; (*out)[12u + 7u] = 0xD1CA2087u;
    (*out)[12u + 8u] = 0x96CEBC1Du; (*out)[12u + 9u] = 0x2DA25966u;
    (*out)[12u + 10u] = 0xBBFD87D2u; (*out)[12u + 11u] = 0x0E2B7EEDu;
}

fn fp12_frobenius_p(a: ptr<function, array<u32, 144>>, n: u32,
                    out: ptr<function, array<u32, 144>>) {
    var a0: array<u32, 72>; fp12_get_c0(a, &a0);
    var a1: array<u32, 72>; fp12_get_c1(a, &a1);
    var r0: array<u32, 72>; fp6_frobenius_p(&a0, n, &r0);
    var r1: array<u32, 72>; fp6_frobenius_p(&a1, n, &r1);

    var coeff: array<u32, 24>;
    if (n == 1u) { frob12_n1(&coeff); }
    else if (n == 2u) { frob12_n2(&coeff); }
    else { frob12_n3(&coeff); }

    var r1_c0: array<u32, 24>; fp6_get_c0(&r1, &r1_c0);
    var r1_c1: array<u32, 24>; fp6_get_c1(&r1, &r1_c1);
    var r1_c2: array<u32, 24>; fp6_get_c2(&r1, &r1_c2);
    var r1_c0_new: array<u32, 24>; fp2_mul_p(&r1_c0, &coeff, &r1_c0_new);
    var r1_c1_new: array<u32, 24>; fp2_mul_p(&r1_c1, &coeff, &r1_c1_new);
    var r1_c2_new: array<u32, 24>; fp2_mul_p(&r1_c2, &coeff, &r1_c2_new);
    var r1_new: array<u32, 72>;
    fp6_set_c0(&r1_new, &r1_c0_new);
    fp6_set_c1(&r1_new, &r1_c1_new);
    fp6_set_c2(&r1_new, &r1_c2_new);

    fp12_set_c0(out, &r0);
    fp12_set_c1(out, &r1_new);
}

// ---------- Private-storage scratches for upper-tower kernels ----------
//
// The full Fp12 call tree blows AGXMetalG13X's function-call stack budget
// when every intermediate sits on the function stack. Move all the multi-
// limb scratches into private storage; the function stack only ever sees
// one Fp2 (96 B). Workgroup size is 1, so each invocation owns these.

// Fp12-level scratches (6 x 144 u32 = 3.4 KB private)
var<private> sp_a: array<u32, 144>;
var<private> sp_b: array<u32, 144>;
var<private> sp_x12_0: array<u32, 144>;
var<private> sp_x12_1: array<u32, 144>;

// Fp6-level scratches (8 x 72 u32 = 2.3 KB private)
var<private> sp_a0: array<u32, 72>;
var<private> sp_a1: array<u32, 72>;
var<private> sp_b0: array<u32, 72>;
var<private> sp_b1: array<u32, 72>;
var<private> sp_t0: array<u32, 72>;
var<private> sp_t1: array<u32, 72>;
var<private> sp_t2: array<u32, 72>;
var<private> sp_t3: array<u32, 72>;
var<private> sp_r0: array<u32, 72>;
var<private> sp_r1: array<u32, 72>;

// Fp2-level scratches for fp6_mul/sqr/inv internals
var<private> sp_a00: array<u32, 24>;
var<private> sp_a01: array<u32, 24>;
var<private> sp_a02: array<u32, 24>;
var<private> sp_b00: array<u32, 24>;
var<private> sp_b01: array<u32, 24>;
var<private> sp_b02: array<u32, 24>;
var<private> sp_u0: array<u32, 24>;
var<private> sp_u1: array<u32, 24>;
var<private> sp_u2: array<u32, 24>;
var<private> sp_u3: array<u32, 24>;
var<private> sp_u4: array<u32, 24>;
var<private> sp_u5: array<u32, 24>;
var<private> sp_u6: array<u32, 24>;
var<private> sp_v0: array<u32, 24>;
var<private> sp_v1: array<u32, 24>;
var<private> sp_v2: array<u32, 24>;

fn fp12_priv_get_c0(a: ptr<private, array<u32, 144>>,
                    out: ptr<private, array<u32, 72>>) {
    for (var i = 0u; i < 72u; i = i + 1u) { (*out)[i] = (*a)[i]; }
}
fn fp12_priv_get_c1(a: ptr<private, array<u32, 144>>,
                    out: ptr<private, array<u32, 72>>) {
    for (var i = 0u; i < 72u; i = i + 1u) { (*out)[i] = (*a)[72u + i]; }
}
fn fp12_priv_set_c0(out: ptr<private, array<u32, 144>>,
                    v: ptr<private, array<u32, 72>>) {
    for (var i = 0u; i < 72u; i = i + 1u) { (*out)[i] = (*v)[i]; }
}
fn fp12_priv_set_c1(out: ptr<private, array<u32, 144>>,
                    v: ptr<private, array<u32, 72>>) {
    for (var i = 0u; i < 72u; i = i + 1u) { (*out)[72u + i] = (*v)[i]; }
}
fn fp6_priv_get_c0(a: ptr<private, array<u32, 72>>,
                   out: ptr<private, array<u32, 24>>) {
    for (var i = 0u; i < 24u; i = i + 1u) { (*out)[i] = (*a)[i]; }
}
fn fp6_priv_get_c1(a: ptr<private, array<u32, 72>>,
                   out: ptr<private, array<u32, 24>>) {
    for (var i = 0u; i < 24u; i = i + 1u) { (*out)[i] = (*a)[24u + i]; }
}
fn fp6_priv_get_c2(a: ptr<private, array<u32, 72>>,
                   out: ptr<private, array<u32, 24>>) {
    for (var i = 0u; i < 24u; i = i + 1u) { (*out)[i] = (*a)[48u + i]; }
}
fn fp6_priv_set_c0(out: ptr<private, array<u32, 72>>,
                   v: ptr<private, array<u32, 24>>) {
    for (var i = 0u; i < 24u; i = i + 1u) { (*out)[i] = (*v)[i]; }
}
fn fp6_priv_set_c1(out: ptr<private, array<u32, 72>>,
                   v: ptr<private, array<u32, 24>>) {
    for (var i = 0u; i < 24u; i = i + 1u) { (*out)[24u + i] = (*v)[i]; }
}
fn fp6_priv_set_c2(out: ptr<private, array<u32, 72>>,
                   v: ptr<private, array<u32, 24>>) {
    for (var i = 0u; i < 24u; i = i + 1u) { (*out)[48u + i] = (*v)[i]; }
}

// ---------- Fp2 ops on private operands ----------
//
// Decompose into raw fp_* leaves directly. Each Fp2 op only ever has at most
// six 12 x u32 stack temporaries (a0, a1, b0, b1, r0, r1). Returning an
// array<u32, 12> from fp_mul/add/sub/neg/sqr/inv lands in a stack slot, and
// AGXMetalG13X tolerates that in the deep call tree because the private
// scratches above absorb the working state.

fn run_fp2_add_pp(a: ptr<private, array<u32, 24>>, b: ptr<private, array<u32, 24>>,
                  out: ptr<private, array<u32, 24>>) {
    var a0: array<u32, 12>;
    var a1: array<u32, 12>;
    var b0: array<u32, 12>;
    var b1: array<u32, 12>;
    for (var i = 0u; i < 12u; i = i + 1u) {
        a0[i] = (*a)[i]; a1[i] = (*a)[12u + i];
        b0[i] = (*b)[i]; b1[i] = (*b)[12u + i];
    }
    let r0 = fp_add(a0, b0);
    let r1 = fp_add(a1, b1);
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = r0[i]; (*out)[12u + i] = r1[i]; }
}
fn run_fp2_sub_pp(a: ptr<private, array<u32, 24>>, b: ptr<private, array<u32, 24>>,
                  out: ptr<private, array<u32, 24>>) {
    var a0: array<u32, 12>;
    var a1: array<u32, 12>;
    var b0: array<u32, 12>;
    var b1: array<u32, 12>;
    for (var i = 0u; i < 12u; i = i + 1u) {
        a0[i] = (*a)[i]; a1[i] = (*a)[12u + i];
        b0[i] = (*b)[i]; b1[i] = (*b)[12u + i];
    }
    let r0 = fp_sub(a0, b0);
    let r1 = fp_sub(a1, b1);
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = r0[i]; (*out)[12u + i] = r1[i]; }
}
fn run_fp2_neg_pp(a: ptr<private, array<u32, 24>>,
                  out: ptr<private, array<u32, 24>>) {
    var a0: array<u32, 12>;
    var a1: array<u32, 12>;
    for (var i = 0u; i < 12u; i = i + 1u) {
        a0[i] = (*a)[i]; a1[i] = (*a)[12u + i];
    }
    let r0 = fp_neg(a0);
    let r1 = fp_neg(a1);
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = r0[i]; (*out)[12u + i] = r1[i]; }
}
fn run_fp2_mul_pp(a: ptr<private, array<u32, 24>>, b: ptr<private, array<u32, 24>>,
                  out: ptr<private, array<u32, 24>>) {
    var a0: array<u32, 12>;
    var a1: array<u32, 12>;
    var b0: array<u32, 12>;
    var b1: array<u32, 12>;
    for (var i = 0u; i < 12u; i = i + 1u) {
        a0[i] = (*a)[i]; a1[i] = (*a)[12u + i];
        b0[i] = (*b)[i]; b1[i] = (*b)[12u + i];
    }
    let aa = fp_mul(a0, b0);
    let bb = fp_mul(a1, b1);
    let sa = fp_add(a0, a1);
    let sb = fp_add(b0, b1);
    let cross = fp_mul(sa, sb);
    let r0 = fp_sub(aa, bb);
    let r1 = fp_sub(fp_sub(cross, aa), bb);
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = r0[i]; (*out)[12u + i] = r1[i]; }
}
fn run_fp2_sqr_pp(a: ptr<private, array<u32, 24>>,
                  out: ptr<private, array<u32, 24>>) {
    var a0: array<u32, 12>;
    var a1: array<u32, 12>;
    for (var i = 0u; i < 12u; i = i + 1u) {
        a0[i] = (*a)[i]; a1[i] = (*a)[12u + i];
    }
    let ab  = fp_mul(a0, a1);
    let sum = fp_add(a0, a1);
    let dif = fp_sub(a0, a1);
    let r0 = fp_mul(sum, dif);
    let r1 = fp_add(ab, ab);
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = r0[i]; (*out)[12u + i] = r1[i]; }
}
fn run_fp2_inv_pp(a: ptr<private, array<u32, 24>>,
                  out: ptr<private, array<u32, 24>>) {
    var a0: array<u32, 12>;
    var a1: array<u32, 12>;
    for (var i = 0u; i < 12u; i = i + 1u) {
        a0[i] = (*a)[i]; a1[i] = (*a)[12u + i];
    }
    let t0 = fp_sqr(a0);
    let t1 = fp_sqr(a1);
    let norm = fp_add(t0, t1);
    let ni = fp_inv(norm);
    let r0 = fp_mul(a0, ni);
    let r1 = fp_neg(fp_mul(a1, ni));
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = r0[i]; (*out)[12u + i] = r1[i]; }
}
fn run_fp2_mul_by_1_plus_u_pp(a: ptr<private, array<u32, 24>>,
                              out: ptr<private, array<u32, 24>>) {
    var a0: array<u32, 12>;
    var a1: array<u32, 12>;
    for (var i = 0u; i < 12u; i = i + 1u) {
        a0[i] = (*a)[i]; a1[i] = (*a)[12u + i];
    }
    let r0 = fp_sub(a0, a1);
    let r1 = fp_add(a0, a1);
    for (var i = 0u; i < 12u; i = i + 1u) { (*out)[i] = r0[i]; (*out)[12u + i] = r1[i]; }
}

// ---------- Fp6 ops on private operands (the heavy ones use private scratches) ----------

fn run_fp6_add_priv(a: ptr<private, array<u32, 72>>, b: ptr<private, array<u32, 72>>,
                    out: ptr<private, array<u32, 72>>) {
    fp6_priv_get_c0(a, &sp_a00); fp6_priv_get_c1(a, &sp_a01); fp6_priv_get_c2(a, &sp_a02);
    fp6_priv_get_c0(b, &sp_b00); fp6_priv_get_c1(b, &sp_b01); fp6_priv_get_c2(b, &sp_b02);
    run_fp2_add_pp(&sp_a00, &sp_b00, &sp_v0);
    run_fp2_add_pp(&sp_a01, &sp_b01, &sp_v1);
    run_fp2_add_pp(&sp_a02, &sp_b02, &sp_v2);
    fp6_priv_set_c0(out, &sp_v0);
    fp6_priv_set_c1(out, &sp_v1);
    fp6_priv_set_c2(out, &sp_v2);
}
fn run_fp6_sub_priv(a: ptr<private, array<u32, 72>>, b: ptr<private, array<u32, 72>>,
                    out: ptr<private, array<u32, 72>>) {
    fp6_priv_get_c0(a, &sp_a00); fp6_priv_get_c1(a, &sp_a01); fp6_priv_get_c2(a, &sp_a02);
    fp6_priv_get_c0(b, &sp_b00); fp6_priv_get_c1(b, &sp_b01); fp6_priv_get_c2(b, &sp_b02);
    run_fp2_sub_pp(&sp_a00, &sp_b00, &sp_v0);
    run_fp2_sub_pp(&sp_a01, &sp_b01, &sp_v1);
    run_fp2_sub_pp(&sp_a02, &sp_b02, &sp_v2);
    fp6_priv_set_c0(out, &sp_v0);
    fp6_priv_set_c1(out, &sp_v1);
    fp6_priv_set_c2(out, &sp_v2);
}
fn run_fp6_neg_priv(a: ptr<private, array<u32, 72>>,
                    out: ptr<private, array<u32, 72>>) {
    fp6_priv_get_c0(a, &sp_a00); fp6_priv_get_c1(a, &sp_a01); fp6_priv_get_c2(a, &sp_a02);
    run_fp2_neg_pp(&sp_a00, &sp_v0);
    run_fp2_neg_pp(&sp_a01, &sp_v1);
    run_fp2_neg_pp(&sp_a02, &sp_v2);
    fp6_priv_set_c0(out, &sp_v0);
    fp6_priv_set_c1(out, &sp_v1);
    fp6_priv_set_c2(out, &sp_v2);
}
fn run_fp6_mul_priv(a: ptr<private, array<u32, 72>>, b: ptr<private, array<u32, 72>>,
                    out: ptr<private, array<u32, 72>>) {
    fp6_priv_get_c0(a, &sp_a00); fp6_priv_get_c1(a, &sp_a01); fp6_priv_get_c2(a, &sp_a02);
    fp6_priv_get_c0(b, &sp_b00); fp6_priv_get_c1(b, &sp_b01); fp6_priv_get_c2(b, &sp_b02);

    // u0 = a0*b0, u1 = a1*b1, u2 = a2*b2
    run_fp2_mul_pp(&sp_a00, &sp_b00, &sp_u0);
    run_fp2_mul_pp(&sp_a01, &sp_b01, &sp_u1);
    run_fp2_mul_pp(&sp_a02, &sp_b02, &sp_u2);

    // r0 = ((a1+a2)(b1+b2) - u1 - u2) * (u+1) + u0
    run_fp2_add_pp(&sp_a01, &sp_a02, &sp_u3);
    run_fp2_add_pp(&sp_b01, &sp_b02, &sp_u4);
    run_fp2_mul_pp(&sp_u3, &sp_u4, &sp_u5);
    run_fp2_sub_pp(&sp_u5, &sp_u1, &sp_u5);
    run_fp2_sub_pp(&sp_u5, &sp_u2, &sp_u5);
    run_fp2_mul_by_1_plus_u_pp(&sp_u5, &sp_u5);
    run_fp2_add_pp(&sp_u5, &sp_u0, &sp_v0);

    // r1 = (a0+a1)(b0+b1) - u0 - u1 + u2*(u+1)
    run_fp2_add_pp(&sp_a00, &sp_a01, &sp_u3);
    run_fp2_add_pp(&sp_b00, &sp_b01, &sp_u4);
    run_fp2_mul_pp(&sp_u3, &sp_u4, &sp_u5);
    run_fp2_sub_pp(&sp_u5, &sp_u0, &sp_u5);
    run_fp2_sub_pp(&sp_u5, &sp_u1, &sp_u5);
    run_fp2_mul_by_1_plus_u_pp(&sp_u2, &sp_u6);
    run_fp2_add_pp(&sp_u5, &sp_u6, &sp_v1);

    // r2 = (a0+a2)(b0+b2) - u0 - u2 + u1
    run_fp2_add_pp(&sp_a00, &sp_a02, &sp_u3);
    run_fp2_add_pp(&sp_b00, &sp_b02, &sp_u4);
    run_fp2_mul_pp(&sp_u3, &sp_u4, &sp_u5);
    run_fp2_sub_pp(&sp_u5, &sp_u0, &sp_u5);
    run_fp2_sub_pp(&sp_u5, &sp_u2, &sp_u5);
    run_fp2_add_pp(&sp_u5, &sp_u1, &sp_v2);

    fp6_priv_set_c0(out, &sp_v0);
    fp6_priv_set_c1(out, &sp_v1);
    fp6_priv_set_c2(out, &sp_v2);
}
fn run_fp6_sqr_priv(a: ptr<private, array<u32, 72>>,
                    out: ptr<private, array<u32, 72>>) {
    fp6_priv_get_c0(a, &sp_a00); fp6_priv_get_c1(a, &sp_a01); fp6_priv_get_c2(a, &sp_a02);

    // u0 = a0^2, u2 = a2^2
    run_fp2_sqr_pp(&sp_a00, &sp_u0);
    run_fp2_sqr_pp(&sp_a02, &sp_u2);
    // u1 = 2*a0*a1, u3 = 2*a1*a2
    run_fp2_mul_pp(&sp_a00, &sp_a01, &sp_u1);
    run_fp2_add_pp(&sp_u1, &sp_u1, &sp_u1);
    run_fp2_mul_pp(&sp_a01, &sp_a02, &sp_u3);
    run_fp2_add_pp(&sp_u3, &sp_u3, &sp_u3);

    // r2 = (a0+a1+a2)^2 - u0 - u2 - u1 - u3
    run_fp2_add_pp(&sp_a00, &sp_a01, &sp_u4);
    run_fp2_add_pp(&sp_u4, &sp_a02, &sp_u4);
    run_fp2_sqr_pp(&sp_u4, &sp_v2);
    run_fp2_sub_pp(&sp_v2, &sp_u0, &sp_v2);
    run_fp2_sub_pp(&sp_v2, &sp_u2, &sp_v2);
    run_fp2_sub_pp(&sp_v2, &sp_u1, &sp_v2);
    run_fp2_sub_pp(&sp_v2, &sp_u3, &sp_v2);

    // r0 = u3*(u+1) + u0
    run_fp2_mul_by_1_plus_u_pp(&sp_u3, &sp_v0);
    run_fp2_add_pp(&sp_v0, &sp_u0, &sp_v0);

    // r1 = u2*(u+1) + u1
    run_fp2_mul_by_1_plus_u_pp(&sp_u2, &sp_v1);
    run_fp2_add_pp(&sp_v1, &sp_u1, &sp_v1);

    fp6_priv_set_c0(out, &sp_v0);
    fp6_priv_set_c1(out, &sp_v1);
    fp6_priv_set_c2(out, &sp_v2);
}
fn run_fp6_inv_priv(a: ptr<private, array<u32, 72>>,
                    out: ptr<private, array<u32, 72>>) {
    fp6_priv_get_c0(a, &sp_a00); fp6_priv_get_c1(a, &sp_a01); fp6_priv_get_c2(a, &sp_a02);

    // c0 = a0^2 - mul_v(a1*a2)        (-> sp_v0)
    run_fp2_sqr_pp(&sp_a00, &sp_v0);
    run_fp2_mul_pp(&sp_a01, &sp_a02, &sp_u0);
    run_fp2_mul_by_1_plus_u_pp(&sp_u0, &sp_u0);
    run_fp2_sub_pp(&sp_v0, &sp_u0, &sp_v0);

    // c1 = mul_v(a2^2) - a0*a1        (-> sp_v1)
    run_fp2_sqr_pp(&sp_a02, &sp_v1);
    run_fp2_mul_by_1_plus_u_pp(&sp_v1, &sp_v1);
    run_fp2_mul_pp(&sp_a00, &sp_a01, &sp_u0);
    run_fp2_sub_pp(&sp_v1, &sp_u0, &sp_v1);

    // c2 = a1^2 - a0*a2               (-> sp_v2)
    run_fp2_sqr_pp(&sp_a01, &sp_v2);
    run_fp2_mul_pp(&sp_a00, &sp_a02, &sp_u0);
    run_fp2_sub_pp(&sp_v2, &sp_u0, &sp_v2);

    // norm = mul_v(c1*a2 + c2*a1) + c0*a0
    run_fp2_mul_pp(&sp_v1, &sp_a02, &sp_u1);
    run_fp2_mul_pp(&sp_v2, &sp_a01, &sp_u2);
    run_fp2_add_pp(&sp_u1, &sp_u2, &sp_u3);
    run_fp2_mul_by_1_plus_u_pp(&sp_u3, &sp_u3);
    run_fp2_mul_pp(&sp_v0, &sp_a00, &sp_u4);
    run_fp2_add_pp(&sp_u3, &sp_u4, &sp_u3);   // norm

    // ni = norm^-1                    (-> sp_u4)
    run_fp2_inv_pp(&sp_u3, &sp_u4);

    // r0 = c0*ni, r1 = c1*ni, r2 = c2*ni
    run_fp2_mul_pp(&sp_v0, &sp_u4, &sp_u0);
    run_fp2_mul_pp(&sp_v1, &sp_u4, &sp_u1);
    run_fp2_mul_pp(&sp_v2, &sp_u4, &sp_u2);
    fp6_priv_set_c0(out, &sp_u0);
    fp6_priv_set_c1(out, &sp_u1);
    fp6_priv_set_c2(out, &sp_u2);
}
fn run_fp6_mul_by_v_priv(a: ptr<private, array<u32, 72>>,
                         out: ptr<private, array<u32, 72>>) {
    fp6_priv_get_c0(a, &sp_a00); fp6_priv_get_c1(a, &sp_a01); fp6_priv_get_c2(a, &sp_a02);
    run_fp2_mul_by_1_plus_u_pp(&sp_a02, &sp_v0);
    fp6_priv_set_c0(out, &sp_v0);
    fp6_priv_set_c1(out, &sp_a00);
    fp6_priv_set_c2(out, &sp_a01);
}

fn fp12_add_priv(a: ptr<private, array<u32, 144>>, b: ptr<private, array<u32, 144>>,
                 out: ptr<private, array<u32, 144>>) {
    fp12_priv_get_c0(a, &sp_a0); fp12_priv_get_c1(a, &sp_a1);
    fp12_priv_get_c0(b, &sp_b0); fp12_priv_get_c1(b, &sp_b1);
    run_fp6_add_priv(&sp_a0, &sp_b0, &sp_r0);
    run_fp6_add_priv(&sp_a1, &sp_b1, &sp_r1);
    fp12_priv_set_c0(out, &sp_r0);
    fp12_priv_set_c1(out, &sp_r1);
}
fn fp12_sub_priv(a: ptr<private, array<u32, 144>>, b: ptr<private, array<u32, 144>>,
                 out: ptr<private, array<u32, 144>>) {
    fp12_priv_get_c0(a, &sp_a0); fp12_priv_get_c1(a, &sp_a1);
    fp12_priv_get_c0(b, &sp_b0); fp12_priv_get_c1(b, &sp_b1);
    run_fp6_sub_priv(&sp_a0, &sp_b0, &sp_r0);
    run_fp6_sub_priv(&sp_a1, &sp_b1, &sp_r1);
    fp12_priv_set_c0(out, &sp_r0);
    fp12_priv_set_c1(out, &sp_r1);
}
fn fp12_conj_priv(a: ptr<private, array<u32, 144>>,
                  out: ptr<private, array<u32, 144>>) {
    fp12_priv_get_c0(a, &sp_a0); fp12_priv_get_c1(a, &sp_a1);
    run_fp6_neg_priv(&sp_a1, &sp_r1);
    fp12_priv_set_c0(out, &sp_a0);
    fp12_priv_set_c1(out, &sp_r1);
}
fn fp12_mul_priv(a: ptr<private, array<u32, 144>>, b: ptr<private, array<u32, 144>>,
                 out: ptr<private, array<u32, 144>>) {
    fp12_priv_get_c0(a, &sp_a0); fp12_priv_get_c1(a, &sp_a1);
    fp12_priv_get_c0(b, &sp_b0); fp12_priv_get_c1(b, &sp_b1);
    run_fp6_mul_priv(&sp_a0, &sp_b0, &sp_t0);
    run_fp6_mul_priv(&sp_a1, &sp_b1, &sp_t1);
    run_fp6_add_priv(&sp_a0, &sp_a1, &sp_t2);
    run_fp6_add_priv(&sp_b0, &sp_b1, &sp_t3);
    run_fp6_mul_priv(&sp_t2, &sp_t3, &sp_r1);
    run_fp6_sub_priv(&sp_r1, &sp_t0, &sp_r1);
    run_fp6_sub_priv(&sp_r1, &sp_t1, &sp_r1);
    run_fp6_mul_by_v_priv(&sp_t1, &sp_t2);
    run_fp6_add_priv(&sp_t0, &sp_t2, &sp_r0);
    fp12_priv_set_c0(out, &sp_r0);
    fp12_priv_set_c1(out, &sp_r1);
}
fn fp12_sqr_priv(a: ptr<private, array<u32, 144>>,
                 out: ptr<private, array<u32, 144>>) {
    fp12_priv_get_c0(a, &sp_a0); fp12_priv_get_c1(a, &sp_a1);
    run_fp6_add_priv(&sp_a0, &sp_a1, &sp_t0);
    run_fp6_mul_by_v_priv(&sp_a1, &sp_t1);
    run_fp6_add_priv(&sp_a0, &sp_t1, &sp_t2);
    run_fp6_mul_priv(&sp_t0, &sp_t2, &sp_t3);
    run_fp6_mul_priv(&sp_a0, &sp_a1, &sp_t1);
    run_fp6_add_priv(&sp_t1, &sp_t1, &sp_r1);
    run_fp6_sub_priv(&sp_t3, &sp_t1, &sp_r0);
    run_fp6_mul_by_v_priv(&sp_t1, &sp_t2);
    run_fp6_sub_priv(&sp_r0, &sp_t2, &sp_r0);
    fp12_priv_set_c0(out, &sp_r0);
    fp12_priv_set_c1(out, &sp_r1);
}
fn fp12_inv_priv(a: ptr<private, array<u32, 144>>,
                 out: ptr<private, array<u32, 144>>) {
    fp12_priv_get_c0(a, &sp_a0); fp12_priv_get_c1(a, &sp_a1);
    run_fp6_sqr_priv(&sp_a0, &sp_t0);
    run_fp6_sqr_priv(&sp_a1, &sp_t1);
    run_fp6_mul_by_v_priv(&sp_t1, &sp_t2);
    run_fp6_sub_priv(&sp_t0, &sp_t2, &sp_t3);
    run_fp6_inv_priv(&sp_t3, &sp_t0);          // ti -> sp_t0
    run_fp6_mul_priv(&sp_a0, &sp_t0, &sp_r0);
    run_fp6_mul_priv(&sp_a1, &sp_t0, &sp_t1);  // r1_pos -> sp_t1
    run_fp6_neg_priv(&sp_t1, &sp_r1);
    fp12_priv_set_c0(out, &sp_r0);
    fp12_priv_set_c1(out, &sp_r1);
}

// Cyclotomic squaring uses six Fp2 squarings (sqr_fp4 ×3) and a handful of
// Fp2 ops. All operands are 24 x u32 = 96 bytes; the function-stack budget
// holds at this size.
fn fp12_cyclotomic_sqr_priv(a: ptr<private, array<u32, 144>>,
                            out: ptr<private, array<u32, 144>>) {
    var fa: array<u32, 144>;
    for (var i = 0u; i < 144u; i = i + 1u) { fa[i] = (*a)[i]; }
    var fr: array<u32, 144>;
    fp12_cyclotomic_sqr_p(&fa, &fr);
    for (var i = 0u; i < 144u; i = i + 1u) { (*out)[i] = fr[i]; }
}

fn fp12_one_p(out: ptr<function, array<u32, 144>>) {
    var onep: array<u32, 24>;
    var zerop: array<u32, 24>;
    for (var i = 0u; i < 24u; i = i + 1u) { zerop[i] = 0u; }
    for (var i = 0u; i < 12u; i = i + 1u) { onep[i] = BLS_R[i]; onep[12u + i] = 0u; }
    var c0: array<u32, 72>;
    fp6_set_c0(&c0, &onep);
    fp6_set_c1(&c0, &zerop);
    fp6_set_c2(&c0, &zerop);
    var c1: array<u32, 72>;
    fp6_set_c0(&c1, &zerop);
    fp6_set_c1(&c1, &zerop);
    fp6_set_c2(&c1, &zerop);
    fp12_set_c0(out, &c0);
    fp12_set_c1(out, &c1);
}

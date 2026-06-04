// WGSL peer of bls_fp12.metal. Fp12 = 144 x u32 = 2 * Fp6 (576 bytes byte-equal blst_fp12).

fn fp12_get_c0(a: array<u32, 144>) -> array<u32, 72> {
    var r: array<u32, 72>;
    for (var i = 0u; i < 72u; i = i + 1u) { r[i] = a[i]; }
    return r;
}
fn fp12_get_c1(a: array<u32, 144>) -> array<u32, 72> {
    var r: array<u32, 72>;
    for (var i = 0u; i < 72u; i = i + 1u) { r[i] = a[72u + i]; }
    return r;
}
fn fp12_pack(c0: array<u32, 72>, c1: array<u32, 72>) -> array<u32, 144> {
    var r: array<u32, 144>;
    for (var i = 0u; i < 72u; i = i + 1u) { r[i] = c0[i]; r[72u + i] = c1[i]; }
    return r;
}

fn fp12_add(a: array<u32, 144>, b: array<u32, 144>) -> array<u32, 144> {
    let r0 = fp6_add(fp12_get_c0(a), fp12_get_c0(b));
    let r1 = fp6_add(fp12_get_c1(a), fp12_get_c1(b));
    return fp12_pack(r0, r1);
}
fn fp12_sub(a: array<u32, 144>, b: array<u32, 144>) -> array<u32, 144> {
    let r0 = fp6_sub(fp12_get_c0(a), fp12_get_c0(b));
    let r1 = fp6_sub(fp12_get_c1(a), fp12_get_c1(b));
    return fp12_pack(r0, r1);
}

// (a0 + a1 v + a2 v^2) * v = a2 (u+1) + a0 v + a1 v^2  (Fp6 in Fp2 layout)
fn fp6_mul_by_v(a: array<u32, 72>) -> array<u32, 72> {
    let r0 = fp2_mul_by_1_plus_u(fp6_get_c2(a));
    let r1 = fp6_get_c0(a);
    let r2 = fp6_get_c1(a);
    return fp6_pack(r0, r1, r2);
}

fn fp12_mul(a: array<u32, 144>, b: array<u32, 144>) -> array<u32, 144> {
    let a0 = fp12_get_c0(a); let a1 = fp12_get_c1(a);
    let b0 = fp12_get_c0(b); let b1 = fp12_get_c1(b);
    let t0 = fp6_mul(a0, b0);
    let t1 = fp6_mul(a1, b1);

    var r1 = fp6_mul(fp6_add(a0, a1), fp6_add(b0, b1));
    r1 = fp6_sub(r1, t0);
    r1 = fp6_sub(r1, t1);

    let r0 = fp6_add(t0, fp6_mul_by_v(t1));
    return fp12_pack(r0, r1);
}

fn fp12_sqr(a: array<u32, 144>) -> array<u32, 144> {
    let a0 = fp12_get_c0(a); let a1 = fp12_get_c1(a);
    var t0 = fp6_add(a0, a1);
    var t1 = fp6_mul_by_v(a1);
    t1 = fp6_add(a0, t1);
    t0 = fp6_mul(t0, t1);

    let t2 = fp6_mul(a0, a1);
    let r1 = fp6_add(t2, t2);
    var r0 = fp6_sub(t0, t2);
    r0 = fp6_sub(r0, fp6_mul_by_v(t2));
    return fp12_pack(r0, r1);
}

fn fp12_conj(a: array<u32, 144>) -> array<u32, 144> {
    let r0 = fp12_get_c0(a);
    let r1 = fp6_neg(fp12_get_c1(a));
    return fp12_pack(r0, r1);
}

fn fp12_inv(a: array<u32, 144>) -> array<u32, 144> {
    let a0 = fp12_get_c0(a); let a1 = fp12_get_c1(a);
    var t0 = fp6_sqr(a0);
    let t1 = fp6_sqr(a1);
    t0 = fp6_sub(t0, fp6_mul_by_v(t1));
    let ti = fp6_inv(t0);

    let r0 = fp6_mul(a0, ti);
    let r1_pos = fp6_mul(a1, ti);
    let r1 = fp6_neg(r1_pos);
    return fp12_pack(r0, r1);
}

// Cyclotomic squaring in Fp12. Mirrors blst's cyclotomic_sqr_fp12 + sqr_fp4.
struct Fp4Pair { r0: array<u32, 24>, r1: array<u32, 24> };

fn sqr_fp4(a0: array<u32, 24>, a1: array<u32, 24>) -> Fp4Pair {
    let t0 = fp2_sqr(a0);
    let t1 = fp2_sqr(a1);
    let sum = fp2_add(a0, a1);

    let r0 = fp2_add(fp2_mul_by_1_plus_u(t1), t0);
    var r1 = fp2_sqr(sum);
    r1 = fp2_sub(r1, t0);
    r1 = fp2_sub(r1, t1);
    return Fp4Pair(r0, r1);
}

fn fp12_cyclotomic_sqr(a: array<u32, 144>) -> array<u32, 144> {
    let a_c0 = fp12_get_c0(a);
    let a_c1 = fp12_get_c1(a);
    let a00 = fp6_get_c0(a_c0); let a01 = fp6_get_c1(a_c0); let a02 = fp6_get_c2(a_c0);
    let a10 = fp6_get_c0(a_c1); let a11 = fp6_get_c1(a_c1); let a12 = fp6_get_c2(a_c1);

    let t_a = sqr_fp4(a00, a11);
    let t_b = sqr_fp4(a10, a02);
    let t_c = sqr_fp4(a01, a12);

    var tmp: array<u32, 24>;

    // r.c0.c0 = 3 t00 - 2 a00
    tmp = fp2_sub(t_a.r0, a00);
    let r00 = fp2_add(fp2_add(tmp, tmp), t_a.r0);

    // r.c0.c1 = 3 t10 - 2 a01
    tmp = fp2_sub(t_b.r0, a01);
    let r01 = fp2_add(fp2_add(tmp, tmp), t_b.r0);

    // r.c0.c2 = 3 t20 - 2 a02
    tmp = fp2_sub(t_c.r0, a02);
    let r02 = fp2_add(fp2_add(tmp, tmp), t_c.r0);

    // r.c1.c0 = 3 (t21 * (u+1)) + 2 a10
    tmp = fp2_mul_by_1_plus_u(t_c.r1);
    var add_v = fp2_add(tmp, a10);
    let r10 = fp2_add(fp2_add(add_v, add_v), tmp);

    // r.c1.c1 = 3 t01 + 2 a11
    add_v = fp2_add(t_a.r1, a11);
    let r11 = fp2_add(fp2_add(add_v, add_v), t_a.r1);

    // r.c1.c2 = 3 t11 + 2 a12
    add_v = fp2_add(t_b.r1, a12);
    let r12 = fp2_add(fp2_add(add_v, add_v), t_b.r1);

    let c0 = fp6_pack(r00, r01, r02);
    let c1 = fp6_pack(r10, r11, r12);
    return fp12_pack(c0, c1);
}

// Frobenius for Fp12.
fn frob12_n1() -> array<u32, 24> {
    let re = array<u32, 12>(
        0xB319D465u, 0x07089552u, 0xB50A8313u, 0xC6695F92u,
        0xD117228Fu, 0x97E83CCCu, 0xB2DC29EEu, 0xA35BAECAu,
        0x5DAACE4Du, 0x1CE393EAu, 0xB0FB66EBu, 0x08F2220Fu);
    let im = array<u32, 12>(
        0x4CE5D646u, 0xB2F66AADu, 0xFC497CECu, 0x5842A06Bu,
        0x2599D394u, 0xCF4895D4u, 0x40A8E8D0u, 0xC11B9CBAu,
        0xE5A0DE89u, 0x2E3813CBu, 0x88847FAFu, 0x110EEFDAu);
    return fp2_pack(re, im);
}
fn frob12_n2() -> array<u32, 24> {
    let re = array<u32, 12>(
        0x798DBA3Au, 0xECFB361Bu, 0x91865A2Cu, 0xC100DDB8u,
        0x232BDA8Eu, 0x0EC08FF1u, 0xF1CA4721u, 0xD5C13CC6u,
        0xBF7B5C04u, 0x47222A47u, 0xE51C5F59u, 0x0110F184u);
    var im: array<u32, 12>; for (var i = 0u; i < 12u; i = i + 1u) { im[i] = 0u; }
    return fp2_pack(re, im);
}
fn frob12_n3() -> array<u32, 24> {
    let re = array<u32, 12>(
        0xA55C9AD1u, 0x3E2F585Du, 0x86C18183u, 0x4294213Du,
        0x8B623732u, 0x382844C8u, 0x19103E18u, 0x92AD2AFDu,
        0xAC7CF0B9u, 0x1D794E4Fu, 0x7D825EC8u, 0x0BD592FCu);
    let im = array<u32, 12>(
        0x5AA30FDAu, 0x7BCFA7A2u, 0x2A927E7Cu, 0xDC17DEC1u,
        0x6B4EBEF1u, 0x2F088DD8u, 0xDA74D4A7u, 0xD1CA2087u,
        0x96CEBC1Du, 0x2DA25966u, 0xBBFD87D2u, 0x0E2B7EEDu);
    return fp2_pack(re, im);
}

fn fp12_frobenius(a: array<u32, 144>, n: u32) -> array<u32, 144> {
    let r0 = fp6_frobenius(fp12_get_c0(a), n);
    var r1 = fp6_frobenius(fp12_get_c1(a), n);

    var coeff: array<u32, 24>;
    if (n == 1u) { coeff = frob12_n1(); }
    else if (n == 2u) { coeff = frob12_n2(); }
    else { coeff = frob12_n3(); }

    let r1_c0 = fp2_mul(fp6_get_c0(r1), coeff);
    let r1_c1 = fp2_mul(fp6_get_c1(r1), coeff);
    let r1_c2 = fp2_mul(fp6_get_c2(r1), coeff);
    r1 = fp6_pack(r1_c0, r1_c1, r1_c2);

    return fp12_pack(r0, r1);
}

fn fp12_one() -> array<u32, 144> {
    let onep = fp2_one_v();
    let zerop = fp2_zero();
    let one6 = fp6_pack(onep, zerop, zerop);
    let zero6 = fp6_pack(zerop, zerop, zerop);
    return fp12_pack(one6, zero6);
}

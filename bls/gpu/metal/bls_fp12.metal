// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Fp12 = Fp6[w] / (w^2 - v) for BLS12-381.
// Layout: struct Fp12 { Fp6 c0, c1; }  ==  blst_fp12 { blst_fp6 fp6[2]; } byte-equal.
// Element c0 + c1 w  with w^2 = v.
//
// Algorithms mirror blst src/fp12_tower.c:
//
// mul (Karatsuba over Fp6):
//   t0 = a0 b0,  t1 = a1 b1
//   r1 = (a0 + a1)(b0 + b1) - t0 - t1
//   r0 = t0 + t1 * v          where (a + b v + c v^2) * v = c (u+1) + a v + b v^2
//
// sqr (Karatsuba):
//   t0 = (a0 + a1)(a0 + a1*v),  t1 = a0 a1
//   r1 = 2 t1
//   r0 = t0 - t1 - t1*v
//
// conjugate:  (c0 + c1 w) -> (c0 - c1 w)  =  c0 + (-c1) w
//
// inv:  (a0 - a1 w) / (a0^2 - a1^2 v)
//
// cyclotomic_sqr:  see blst (uses sqr_fp4). Implementation mirrors blst exactly.
//
// Frobenius coefficients hardcoded from blst src/fp12_tower.c lines 706-731,
// already in Montgomery form.

#ifndef BLS_FP12_INLINES
#define BLS_FP12_INLINES

#define BLS_FP6_NO_KERNELS
#define BLS_FP2_NO_KERNELS
#include "bls_fp6.metal"
#undef BLS_FP6_NO_KERNELS
#undef BLS_FP2_NO_KERNELS

struct Fp12 { Fp6 c0, c1; };

inline Fp12 fp12_add(Fp12 a, Fp12 b) {
    Fp12 r;
    r.c0 = fp6_add(a.c0, b.c0);
    r.c1 = fp6_add(a.c1, b.c1);
    return r;
}

inline Fp12 fp12_sub(Fp12 a, Fp12 b) {
    Fp12 r;
    r.c0 = fp6_sub(a.c0, b.c0);
    r.c1 = fp6_sub(a.c1, b.c1);
    return r;
}

// (a0 + a1 v + a2 v^2) * v = a2 (u+1) + a0 v + a1 v^2
inline Fp6 fp6_mul_by_v(Fp6 a) {
    Fp6 r;
    r.c0 = fp2_mul_by_1_plus_u(a.c2);
    r.c1 = a.c0;
    r.c2 = a.c1;
    return r;
}

inline Fp12 fp12_mul(Fp12 a, Fp12 b) {
    Fp6 t0 = fp6_mul(a.c0, b.c0);
    Fp6 t1 = fp6_mul(a.c1, b.c1);

    // r1 = (a0 + a1)(b0 + b1) - t0 - t1
    Fp6 sa = fp6_add(a.c0, a.c1);
    Fp6 sb = fp6_add(b.c0, b.c1);
    Fp6 r1 = fp6_mul(sa, sb);
    r1 = fp6_sub(r1, t0);
    r1 = fp6_sub(r1, t1);

    // r0 = t0 + t1 * v
    Fp6 r0 = fp6_add(t0, fp6_mul_by_v(t1));

    Fp12 r; r.c0 = r0; r.c1 = r1; return r;
}

inline Fp12 fp12_sqr(Fp12 a) {
    // Karatsuba: t0 = (a0+a1)(a0 + a1*v),   t1 = a0 a1
    // r1 = 2 t1
    // r0 = t0 - t1 - t1*v
    Fp6 t0 = fp6_add(a.c0, a.c1);
    Fp6 t1 = fp6_mul_by_v(a.c1);
    t1 = fp6_add(a.c0, t1);
    t0 = fp6_mul(t0, t1);

    Fp6 t2 = fp6_mul(a.c0, a.c1);

    Fp12 r;
    // r1 = 2 t2
    r.c1 = fp6_add(t2, t2);

    // r0 = t0 - t2 - t2*v
    Fp6 r0 = fp6_sub(t0, t2);
    r0 = fp6_sub(r0, fp6_mul_by_v(t2));
    r.c0 = r0;
    return r;
}

inline Fp12 fp12_conj(Fp12 a) {
    Fp12 r;
    r.c0 = a.c0;
    r.c1 = fp6_neg(a.c1);
    return r;
}

inline Fp12 fp12_inv(Fp12 a) {
    Fp6 t0 = fp6_sqr(a.c0);
    Fp6 t1 = fp6_sqr(a.c1);
    t0 = fp6_sub(t0, fp6_mul_by_v(t1));    // a0^2 - a1^2 * v
    Fp6 ti = fp6_inv(t0);

    Fp12 r;
    r.c0 = fp6_mul(a.c0, ti);
    r.c1 = fp6_mul(a.c1, ti);
    r.c1 = fp6_neg(r.c1);
    return r;
}

// Cyclotomic squaring on Fp12. Defined for elements in the cyclotomic
// subgroup G_phi_12 (i.e., output of the easy part of final exponentiation).
// Mirrors blst's cyclotomic_sqr_fp12 + sqr_fp4 exactly.
inline void sqr_fp4(thread Fp2& r0, thread Fp2& r1, Fp2 a0, Fp2 a1) {
    Fp2 t0 = fp2_sqr(a0);
    Fp2 t1 = fp2_sqr(a1);
    Fp2 sum = fp2_add(a0, a1);

    r0 = fp2_add(fp2_mul_by_1_plus_u(t1), t0);

    r1 = fp2_sqr(sum);
    r1 = fp2_sub(r1, t0);
    r1 = fp2_sub(r1, t1);
}

inline Fp12 fp12_cyclotomic_sqr(Fp12 a) {
    Fp2 t00, t01, t10, t11, t20, t21;
    sqr_fp4(t00, t01, a.c0.c0, a.c1.c1);
    sqr_fp4(t10, t11, a.c1.c0, a.c0.c2);
    sqr_fp4(t20, t21, a.c0.c1, a.c1.c2);

    Fp12 r;
    // r.c0.c0 = 3 t00 - 2 a.c0.c0
    Fp2 tmp = fp2_sub(t00, a.c0.c0);
    r.c0.c0 = fp2_add(fp2_add(tmp, tmp), t00);

    // r.c0.c1 = 3 t10 - 2 a.c0.c1
    tmp = fp2_sub(t10, a.c0.c1);
    r.c0.c1 = fp2_add(fp2_add(tmp, tmp), t10);

    // r.c0.c2 = 3 t20 - 2 a.c0.c2
    tmp = fp2_sub(t20, a.c0.c2);
    r.c0.c2 = fp2_add(fp2_add(tmp, tmp), t20);

    // r.c1.c0 = 3 (t21 * (u+1)) + 2 a.c1.c0
    tmp = fp2_mul_by_1_plus_u(t21);
    Fp2 add = fp2_add(tmp, a.c1.c0);
    r.c1.c0 = fp2_add(fp2_add(add, add), tmp);

    // r.c1.c1 = 3 t01 + 2 a.c1.c1
    add = fp2_add(t01, a.c1.c1);
    r.c1.c1 = fp2_add(fp2_add(add, add), t01);

    // r.c1.c2 = 3 t11 + 2 a.c1.c2
    add = fp2_add(t11, a.c1.c2);
    r.c1.c2 = fp2_add(fp2_add(add, add), t11);

    return r;
}

// Frobenius coefficients for Fp12 (Montgomery form), from blst src/fp12_tower.c
// lines 708-723.   coeffs[n-1] = (u + 1)^((p^n - 1) / 6)  in Fp2.

constant uint384 FP12_FROB_RE_N1 = {{
    0x07089552B319D465UL, 0xC6695F92B50A8313UL, 0x97E83CCCD117228FUL,
    0xA35BAECAB2DC29EEUL, 0x1CE393EA5DAACE4DUL, 0x08F2220FB0FB66EBUL
}};
constant uint384 FP12_FROB_IM_N1 = {{
    0xB2F66AAD4CE5D646UL, 0x5842A06BFC497CECUL, 0xCF4895D42599D394UL,
    0xC11B9CBA40A8E8D0UL, 0x2E3813CBE5A0DE89UL, 0x110EEFDA88847FAFUL
}};

constant uint384 FP12_FROB_RE_N2 = {{
    0xECFB361B798DBA3AUL, 0xC100DDB891865A2CUL, 0x0EC08FF1232BDA8EUL,
    0xD5C13CC6F1CA4721UL, 0x47222A47BF7B5C04UL, 0x0110F184E51C5F59UL
}};
constant uint384 FP12_FROB_IM_N2 = {{0,0,0,0,0,0}};

constant uint384 FP12_FROB_RE_N3 = {{
    0x3E2F585DA55C9AD1UL, 0x4294213D86C18183UL, 0x382844C88B623732UL,
    0x92AD2AFD19103E18UL, 0x1D794E4FAC7CF0B9UL, 0x0BD592FC7D825EC8UL
}};
constant uint384 FP12_FROB_IM_N3 = {{
    0x7BCFA7A25AA30FDAUL, 0xDC17DEC12A927E7CUL, 0x2F088DD86B4EBEF1UL,
    0xD1CA2087DA74D4A7UL, 0x2DA2596696CEBC1DUL, 0x0E2B7EEDBBFD87D2UL
}};

inline Fp12 fp12_frobenius(Fp12 a, uint n) {
    Fp6 r0 = fp6_frobenius(a.c0, n);
    Fp6 r1 = fp6_frobenius(a.c1, n);

    Fp2 coeff;
    if (n == 1u) {
        coeff.c0 = FP12_FROB_RE_N1; coeff.c1 = FP12_FROB_IM_N1;
    } else if (n == 2u) {
        coeff.c0 = FP12_FROB_RE_N2; coeff.c1 = FP12_FROB_IM_N2;
    } else {
        coeff.c0 = FP12_FROB_RE_N3; coeff.c1 = FP12_FROB_IM_N3;
    }
    r1.c0 = fp2_mul(r1.c0, coeff);
    r1.c1 = fp2_mul(r1.c1, coeff);
    r1.c2 = fp2_mul(r1.c2, coeff);

    Fp12 r; r.c0 = r0; r.c1 = r1; return r;
}

#endif // BLS_FP12_INLINES

// =============================================================================
// Kernels — buffer element size = 576 bytes (sizeof(Fp12) = 2 * 288).
// =============================================================================

kernel void k_fp12_add(
    device const Fp12* a [[buffer(0)]],
    device const Fp12* b [[buffer(1)]],
    device       Fp12* out [[buffer(2)]],
    constant uint& n [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp12_add(a[tid], b[tid]);
}

kernel void k_fp12_sub(
    device const Fp12* a [[buffer(0)]],
    device const Fp12* b [[buffer(1)]],
    device       Fp12* out [[buffer(2)]],
    constant uint& n [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp12_sub(a[tid], b[tid]);
}

kernel void k_fp12_mul(
    device const Fp12* a [[buffer(0)]],
    device const Fp12* b [[buffer(1)]],
    device       Fp12* out [[buffer(2)]],
    constant uint& n [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp12_mul(a[tid], b[tid]);
}

kernel void k_fp12_sqr(
    device const Fp12* a [[buffer(0)]],
    device       Fp12* out [[buffer(1)]],
    constant uint& n [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp12_sqr(a[tid]);
}

kernel void k_fp12_inv(
    device const Fp12* a [[buffer(0)]],
    device       Fp12* out [[buffer(1)]],
    constant uint& n [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp12_inv(a[tid]);
}

kernel void k_fp12_conj(
    device const Fp12* a [[buffer(0)]],
    device       Fp12* out [[buffer(1)]],
    constant uint& n [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp12_conj(a[tid]);
}

kernel void k_fp12_cyclo_sqr(
    device const Fp12* a [[buffer(0)]],
    device       Fp12* out [[buffer(1)]],
    constant uint& n [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp12_cyclotomic_sqr(a[tid]);
}

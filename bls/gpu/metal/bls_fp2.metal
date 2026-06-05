// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Fp2 = Fp[u]/(u^2 + 1) for BLS12-381.
// Layout: struct Fp2 { Fp c0, c1; }  ==  blst_fp2 { blst_fp fp[2]; } byte-for-byte.
// Element a + b*u stored as { c0=a, c1=b } in Montgomery form.
//
// Algorithms mirror blst src/fp12_tower.c:
//   add/sub/neg : componentwise
//   mul         : Karatsuba
//                   (a0 + a1 u)(b0 + b1 u)
//                   = (a0 b0 - a1 b1) + ((a0+a1)(b0+b1) - a0 b0 - a1 b1) u
//   sqr         : complex squaring  (a + b u)^2 = (a-b)(a+b) + 2 a b u
//   inv         : a^(-1) = (c0 - c1 u) / (c0^2 + c1^2)
//   conj        : (a + b u) -> (a - b u)
//   frobenius_n : conj when n odd, identity when n even (since p ≡ 3 mod 4)
//
// Inline ops live behind a header guard (BLS_FP2_INLINES) so this file can be
// #included by bls_fp6.metal / bls_fp12.metal for type+ops without redefining
// kernels (those are guarded by BLS_FP2_NO_KERNELS).

#ifndef BLS_FP2_INLINES
#define BLS_FP2_INLINES

#include "bls_fp_ops.h.metal"

struct Fp2 { uint384 c0, c1; };

inline Fp2 fp2_add(Fp2 a, Fp2 b) {
    Fp2 r; r.c0 = fp_add(a.c0, b.c0); r.c1 = fp_add(a.c1, b.c1); return r;
}

inline Fp2 fp2_sub(Fp2 a, Fp2 b) {
    Fp2 r; r.c0 = fp_sub(a.c0, b.c0); r.c1 = fp_sub(a.c1, b.c1); return r;
}

inline Fp2 fp2_neg(Fp2 a) {
    Fp2 r; r.c0 = fp_neg(a.c0); r.c1 = fp_neg(a.c1); return r;
}

inline Fp2 fp2_mul(Fp2 a, Fp2 b) {
    uint384 aa = fp_mul(a.c0, b.c0);
    uint384 bb = fp_mul(a.c1, b.c1);
    uint384 sa = fp_add(a.c0, a.c1);
    uint384 sb = fp_add(b.c0, b.c1);
    uint384 cross = fp_mul(sa, sb);
    Fp2 r;
    r.c0 = fp_sub(aa, bb);
    r.c1 = fp_sub(fp_sub(cross, aa), bb);
    return r;
}

inline Fp2 fp2_sqr(Fp2 a) {
    uint384 ab  = fp_mul(a.c0, a.c1);
    uint384 sum = fp_add(a.c0, a.c1);
    uint384 dif = fp_sub(a.c0, a.c1);
    Fp2 r;
    r.c0 = fp_mul(sum, dif);
    r.c1 = fp_add(ab, ab);
    return r;
}

inline Fp2 fp2_conj(Fp2 a) {
    Fp2 r; r.c0 = a.c0; r.c1 = fp_neg(a.c1); return r;
}

inline Fp2 fp2_inv(Fp2 a) {
    uint384 t0 = fp_sqr(a.c0);
    uint384 t1 = fp_sqr(a.c1);
    uint384 norm = fp_add(t0, t1);
    uint384 ni = fp_inv(norm);
    Fp2 r;
    r.c0 = fp_mul(a.c0, ni);
    r.c1 = fp_neg(fp_mul(a.c1, ni));
    return r;
}

inline Fp2 fp2_frobenius(Fp2 a, uint n) {
    return ((n & 1u) == 1u) ? fp2_conj(a) : a;
}

// (a + b u)(1 + u) = (a - b) + (a + b) u
inline Fp2 fp2_mul_by_1_plus_u(Fp2 a) {
    Fp2 r;
    r.c0 = fp_sub(a.c0, a.c1);
    r.c1 = fp_add(a.c0, a.c1);
    return r;
}

#endif // BLS_FP2_INLINES

// =============================================================================
// Kernels — emitted only when this file is the primary translation unit.
// Higher-tower files #define BLS_FP2_NO_KERNELS before #including.
// Buffer element size = 96 bytes (sizeof(Fp2) = 2 * 48).
// =============================================================================

#ifndef BLS_FP2_NO_KERNELS

kernel void k_fp2_add(
    device const Fp2* a    [[buffer(0)]],
    device const Fp2* b    [[buffer(1)]],
    device       Fp2* out  [[buffer(2)]],
    constant uint& n       [[buffer(3)]],
    uint tid               [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp2_add(a[tid], b[tid]);
}

kernel void k_fp2_sub(
    device const Fp2* a    [[buffer(0)]],
    device const Fp2* b    [[buffer(1)]],
    device       Fp2* out  [[buffer(2)]],
    constant uint& n       [[buffer(3)]],
    uint tid               [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp2_sub(a[tid], b[tid]);
}

kernel void k_fp2_mul(
    device const Fp2* a    [[buffer(0)]],
    device const Fp2* b    [[buffer(1)]],
    device       Fp2* out  [[buffer(2)]],
    constant uint& n       [[buffer(3)]],
    uint tid               [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp2_mul(a[tid], b[tid]);
}

kernel void k_fp2_sqr(
    device const Fp2* a    [[buffer(0)]],
    device       Fp2* out  [[buffer(1)]],
    constant uint& n       [[buffer(2)]],
    uint tid               [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp2_sqr(a[tid]);
}

kernel void k_fp2_inv(
    device const Fp2* a    [[buffer(0)]],
    device       Fp2* out  [[buffer(1)]],
    constant uint& n       [[buffer(2)]],
    uint tid               [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp2_inv(a[tid]);
}

kernel void k_fp2_conj(
    device const Fp2* a    [[buffer(0)]],
    device       Fp2* out  [[buffer(1)]],
    constant uint& n       [[buffer(2)]],
    uint tid               [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp2_conj(a[tid]);
}

#endif // BLS_FP2_NO_KERNELS

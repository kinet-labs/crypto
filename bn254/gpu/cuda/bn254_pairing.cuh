// First-party CUDA tower (Fp2/Fp6/Fp12 + G2) and optimal-ate pairing kernel
// for bn254. Included by bn254.cu inside its KINET_BN254_HAVE_CUDA block, so it
// compiles as part of the same translation unit and reuses U256 / Fp ops /
// G1Aff / __constant__ K_P from there.
//
// Algorithm transliteration of bn254/cpp/{bn254_fp2,bn254_fp6,bn254_fp12,
// bn254_g2,bn254_pairing}. The CPU body is the algorithmic oracle. Frobenius
// constants are emitted from the CPU body via gen_pairing_constants -- single
// producer, drift impossible.
//
// Wire format:
//   G2Affine = 18 x u64 LE (x.a0[4] || x.a1[4] || y.a0[4] || y.a1[4] || inf[1] || pad[1])
//   Fp2      = 8  x u64 LE (a0[4] || a1[4])
//   Fp12     = 48 x u64 LE (12 x Fp2 in c0.b0..c1.b2 order)

#ifndef KINET_BN254_PAIRING_CUH
#define KINET_BN254_PAIRING_CUH

// =============================================================================
// Tower types (Fp2 already declared in bn254.cu host scope -- do not redefine).
// =============================================================================

struct Fp6_  { Fp2 b0, b1, b2; };
struct Fp12_ { Fp6_ c0, c1; };
struct G2Aff { Fp2 x, y; int inf; };
struct G2Proj { Fp2 x, y, z; };

// Frobenius constants emitted from CPU body. Single-producer codegen.
#include "bn254_pairing_consts_cuda.cuh"

// =============================================================================
// Fp2 = Fp[u]/(u^2 + 1) -- Karatsuba mul, complex-square sqr.
// =============================================================================

__device__ __forceinline__ Fp2 fp2_zero_() {
    Fp2 r;
    #pragma unroll
    for (int i = 0; i < 4; ++i) { r.a0.limbs[i] = 0; r.a1.limbs[i] = 0; }
    return r;
}

__device__ __forceinline__ bool fp2_is_zero_(const Fp2& x) {
    return u256_is_zero(x.a0) && u256_is_zero(x.a1);
}

__device__ __forceinline__ Fp2 fp2_one_() {
    Fp2 r; r.a0 = to_mont_fp(u256_from_limbs(1,0,0,0));
    #pragma unroll
    for (int i = 0; i < 4; ++i) r.a1.limbs[i] = 0;
    return r;
}

__device__ __forceinline__ Fp2 fp2_add_(const Fp2& x, const Fp2& y) {
    Fp2 r; r.a0 = fp_add(x.a0, y.a0); r.a1 = fp_add(x.a1, y.a1);
    return r;
}

__device__ __forceinline__ Fp2 fp2_sub_(const Fp2& x, const Fp2& y) {
    Fp2 r; r.a0 = fp_sub(x.a0, y.a0); r.a1 = fp_sub(x.a1, y.a1);
    return r;
}

__device__ __forceinline__ Fp2 fp2_neg_(const Fp2& x) {
    Fp2 r; r.a0 = fp_neg(x.a0); r.a1 = fp_neg(x.a1);
    return r;
}

__device__ __forceinline__ Fp2 fp2_double_(const Fp2& x) {
    Fp2 r; r.a0 = fp_add(x.a0, x.a0); r.a1 = fp_add(x.a1, x.a1);
    return r;
}

__device__ __forceinline__ Fp2 fp2_conjugate_(const Fp2& x) {
    Fp2 r; r.a0 = x.a0; r.a1 = fp_neg(x.a1);
    return r;
}

__device__ __forceinline__ Fp2 fp2_mul_by_fp_(const Fp2& x, const U256& y) {
    Fp2 r; r.a0 = fp_mul(x.a0, y); r.a1 = fp_mul(x.a1, y);
    return r;
}

// Karatsuba: matches CPU fp2_mul exactly.
__device__ Fp2 fp2_mul_(const Fp2& x, const Fp2& y) {
    U256 a = fp_mul(fp_add(x.a0, x.a1), fp_add(y.a0, y.a1));
    U256 b = fp_mul(x.a0, y.a0);
    U256 c = fp_mul(x.a1, y.a1);
    Fp2 r;
    r.a1 = fp_sub(fp_sub(a, b), c);
    r.a0 = fp_sub(b, c);
    return r;
}

__device__ Fp2 fp2_sqr_(const Fp2& x) {
    U256 a = fp_mul(fp_add(x.a0, x.a1), fp_sub(x.a0, x.a1));
    U256 b = fp_mul(x.a0, x.a1);
    Fp2 r; r.a0 = a; r.a1 = fp_add(b, b);
    return r;
}

__device__ Fp2 fp2_inv_(const Fp2& x) {
    U256 t0 = fp_sqr(x.a0);
    U256 t1 = fp_sqr(x.a1);
    U256 t  = fp_add(t0, t1);
    U256 ti = fp_inv(t);
    Fp2 r;
    r.a0 = fp_mul(x.a0, ti);
    r.a1 = fp_neg(fp_mul(x.a1, ti));
    return r;
}

// (a0 + a1*u) * (9 + u): 9*a0 = 8*a0 + a0 (three doublings + add).
__device__ Fp2 fp2_mul_by_nonres_(const Fp2& x) {
    U256 t0 = fp_add(x.a0, x.a0);
    t0 = fp_add(t0, t0);
    t0 = fp_add(t0, t0);  // 8 a0
    U256 t1 = fp_add(x.a1, x.a1);
    t1 = fp_add(t1, t1);
    t1 = fp_add(t1, t1);  // 8 a1
    Fp2 r;
    r.a0 = fp_sub(fp_add(t0, x.a0), x.a1);  // 9 a0 - a1
    r.a1 = fp_add(fp_add(t1, x.a1), x.a0);  // 9 a1 + a0
    return r;
}

// Multiplies by (9+u)^-1. Constant computed once per invocation; pairing usage
// only hits this for the b-twist coefficient and inside line-evaluation, so
// the cost is amortised.
__device__ Fp2 fp2_mul_by_nonres_inv_(const Fp2& x) {
    Fp2 nr;
    nr.a0 = to_mont_fp(u256_from_limbs(9,0,0,0));
    nr.a1 = to_mont_fp(u256_from_limbs(1,0,0,0));
    Fp2 inv_nr = fp2_inv_(nr);
    return fp2_mul_(x, inv_nr);
}

// =============================================================================
// Fp6 = Fp2[v]/(v^3 - (9+u)) -- Algorithms 13/16/17, eprint 2010/354.
// =============================================================================

__device__ __forceinline__ Fp6_ fp6_zero_() {
    Fp6_ r; r.b0 = fp2_zero_(); r.b1 = fp2_zero_(); r.b2 = fp2_zero_();
    return r;
}
__device__ __forceinline__ Fp6_ fp6_one_() {
    Fp6_ r; r.b0 = fp2_one_(); r.b1 = fp2_zero_(); r.b2 = fp2_zero_();
    return r;
}
__device__ __forceinline__ Fp6_ fp6_add_(const Fp6_& x, const Fp6_& y) {
    Fp6_ r; r.b0 = fp2_add_(x.b0, y.b0); r.b1 = fp2_add_(x.b1, y.b1); r.b2 = fp2_add_(x.b2, y.b2);
    return r;
}
__device__ __forceinline__ Fp6_ fp6_sub_(const Fp6_& x, const Fp6_& y) {
    Fp6_ r; r.b0 = fp2_sub_(x.b0, y.b0); r.b1 = fp2_sub_(x.b1, y.b1); r.b2 = fp2_sub_(x.b2, y.b2);
    return r;
}
__device__ __forceinline__ Fp6_ fp6_neg_(const Fp6_& x) {
    Fp6_ r; r.b0 = fp2_neg_(x.b0); r.b1 = fp2_neg_(x.b1); r.b2 = fp2_neg_(x.b2);
    return r;
}
__device__ __forceinline__ Fp6_ fp6_double_(const Fp6_& x) {
    Fp6_ r; r.b0 = fp2_double_(x.b0); r.b1 = fp2_double_(x.b1); r.b2 = fp2_double_(x.b2);
    return r;
}
__device__ __forceinline__ Fp6_ fp6_mul_by_nonres_(const Fp6_& x) {
    Fp6_ r; r.b0 = fp2_mul_by_nonres_(x.b2); r.b1 = x.b0; r.b2 = x.b1;
    return r;
}

__device__ Fp6_ fp6_mul_(const Fp6_& x, const Fp6_& y) {
    Fp2 t0 = fp2_mul_(x.b0, y.b0);
    Fp2 t1 = fp2_mul_(x.b1, y.b1);
    Fp2 t2 = fp2_mul_(x.b2, y.b2);

    Fp2 c0 = fp2_add_(x.b1, x.b2);
    Fp2 tmp = fp2_add_(y.b1, y.b2);
    c0 = fp2_mul_(c0, tmp);
    c0 = fp2_sub_(c0, t1);
    c0 = fp2_sub_(c0, t2);
    c0 = fp2_mul_by_nonres_(c0);
    c0 = fp2_add_(c0, t0);

    Fp2 c1 = fp2_add_(x.b0, x.b1);
    tmp = fp2_add_(y.b0, y.b1);
    c1 = fp2_mul_(c1, tmp);
    c1 = fp2_sub_(c1, t0);
    c1 = fp2_sub_(c1, t1);
    Fp2 t2_nr = fp2_mul_by_nonres_(t2);
    c1 = fp2_add_(c1, t2_nr);

    Fp2 c2 = fp2_add_(x.b0, x.b2);
    tmp = fp2_add_(y.b0, y.b2);
    c2 = fp2_mul_(c2, tmp);
    c2 = fp2_sub_(c2, t0);
    c2 = fp2_sub_(c2, t2);
    c2 = fp2_add_(c2, t1);

    Fp6_ r; r.b0 = c0; r.b1 = c1; r.b2 = c2;
    return r;
}

__device__ Fp6_ fp6_sqr_(const Fp6_& x) {
    Fp2 c4 = fp2_mul_(x.b0, x.b1);
    c4 = fp2_double_(c4);
    Fp2 c5 = fp2_sqr_(x.b2);
    Fp2 c1 = fp2_mul_by_nonres_(c5);
    c1 = fp2_add_(c1, c4);
    Fp2 c2 = fp2_sub_(c4, c5);
    Fp2 c3 = fp2_sqr_(x.b0);
    Fp2 c4b = fp2_sub_(x.b0, x.b1);
    c4b = fp2_add_(c4b, x.b2);
    Fp2 c5b = fp2_mul_(x.b1, x.b2);
    c5b = fp2_double_(c5b);
    c4b = fp2_sqr_(c4b);
    Fp2 c0 = fp2_mul_by_nonres_(c5b);
    c0 = fp2_add_(c0, c3);

    Fp2 z2 = fp2_add_(c2, c4b);
    z2 = fp2_add_(z2, c5b);
    z2 = fp2_sub_(z2, c3);

    Fp6_ r; r.b0 = c0; r.b1 = c1; r.b2 = z2;
    return r;
}

__device__ Fp6_ fp6_inv_(const Fp6_& x) {
    Fp2 t0 = fp2_sqr_(x.b0);
    Fp2 t1 = fp2_sqr_(x.b1);
    Fp2 t2 = fp2_sqr_(x.b2);
    Fp2 t3 = fp2_mul_(x.b0, x.b1);
    Fp2 t4 = fp2_mul_(x.b0, x.b2);
    Fp2 t5 = fp2_mul_(x.b1, x.b2);

    Fp2 c0 = fp2_mul_by_nonres_(t5);
    c0 = fp2_neg_(c0);
    c0 = fp2_add_(c0, t0);

    Fp2 c1 = fp2_mul_by_nonres_(t2);
    c1 = fp2_sub_(c1, t3);

    Fp2 c2 = fp2_sub_(t1, t4);

    Fp2 t6 = fp2_mul_(x.b0, c0);
    Fp2 d1 = fp2_mul_(x.b2, c1);
    Fp2 d2 = fp2_mul_(x.b1, c2);
    Fp2 d  = fp2_add_(d1, d2);
    d = fp2_mul_by_nonres_(d);
    t6 = fp2_add_(t6, d);
    Fp2 t6_inv = fp2_inv_(t6);

    Fp6_ r;
    r.b0 = fp2_mul_(c0, t6_inv);
    r.b1 = fp2_mul_(c1, t6_inv);
    r.b2 = fp2_mul_(c2, t6_inv);
    return r;
}

__device__ Fp6_ fp6_mul_by_01_(const Fp6_& z, const Fp2& c0, const Fp2& c1) {
    Fp2 a = fp2_mul_(z.b0, c0);
    Fp2 b = fp2_mul_(z.b1, c1);

    Fp2 tmp = fp2_add_(z.b1, z.b2);
    Fp2 t0 = fp2_mul_(c1, tmp);
    t0 = fp2_sub_(t0, b);
    t0 = fp2_mul_by_nonres_(t0);
    t0 = fp2_add_(t0, a);

    tmp = fp2_add_(z.b0, z.b2);
    Fp2 t2 = fp2_mul_(c0, tmp);
    t2 = fp2_sub_(t2, a);
    t2 = fp2_add_(t2, b);

    Fp2 t1 = fp2_add_(c0, c1);
    tmp = fp2_add_(z.b0, z.b1);
    t1 = fp2_mul_(t1, tmp);
    t1 = fp2_sub_(t1, a);
    t1 = fp2_sub_(t1, b);

    Fp6_ r; r.b0 = t0; r.b1 = t1; r.b2 = t2;
    return r;
}

__device__ Fp6_ fp6_mul_by_fp2_(const Fp6_& z, const Fp2& y) {
    Fp6_ r;
    r.b0 = fp2_mul_(z.b0, y);
    r.b1 = fp2_mul_(z.b1, y);
    r.b2 = fp2_mul_(z.b2, y);
    return r;
}

// =============================================================================
// Fp12 = Fp6[w]/(w^2 - v)
// =============================================================================

__device__ __forceinline__ Fp12_ fp12_zero_() { Fp12_ r; r.c0 = fp6_zero_(); r.c1 = fp6_zero_(); return r; }
__device__ __forceinline__ Fp12_ fp12_one_()  { Fp12_ r; r.c0 = fp6_one_();  r.c1 = fp6_zero_(); return r; }

__device__ bool fp12_is_one_(const Fp12_& z) {
    Fp12_ one = fp12_one_();
    return fp2_is_zero_(z.c1.b0) && fp2_is_zero_(z.c1.b1) && fp2_is_zero_(z.c1.b2)
        && fp2_is_zero_(z.c0.b1) && fp2_is_zero_(z.c0.b2)
        && u256_is_zero(z.c0.b0.a1)
        && u256_eq(z.c0.b0.a0, one.c0.b0.a0);
}

__device__ __forceinline__ Fp12_ fp12_add_(const Fp12_& x, const Fp12_& y) {
    Fp12_ r; r.c0 = fp6_add_(x.c0, y.c0); r.c1 = fp6_add_(x.c1, y.c1); return r;
}
__device__ __forceinline__ Fp12_ fp12_sub_(const Fp12_& x, const Fp12_& y) {
    Fp12_ r; r.c0 = fp6_sub_(x.c0, y.c0); r.c1 = fp6_sub_(x.c1, y.c1); return r;
}
__device__ __forceinline__ Fp12_ fp12_neg_(const Fp12_& x) {
    Fp12_ r; r.c0 = fp6_neg_(x.c0); r.c1 = fp6_neg_(x.c1); return r;
}
__device__ __forceinline__ Fp12_ fp12_conjugate_(const Fp12_& x) {
    Fp12_ r; r.c0 = x.c0; r.c1 = fp6_neg_(x.c1); return r;
}

__device__ Fp12_ fp12_mul_(const Fp12_& x, const Fp12_& y) {
    Fp6_ a = fp6_add_(x.c0, x.c1);
    Fp6_ b = fp6_add_(y.c0, y.c1);
    a = fp6_mul_(a, b);
    b = fp6_mul_(x.c0, y.c0);
    Fp6_ c = fp6_mul_(x.c1, y.c1);
    Fp12_ r;
    r.c1 = fp6_sub_(fp6_sub_(a, b), c);
    r.c0 = fp6_add_(fp6_mul_by_nonres_(c), b);
    return r;
}

__device__ Fp12_ fp12_sqr_(const Fp12_& x) {
    Fp6_ c0 = fp6_sub_(x.c0, x.c1);
    Fp6_ c3 = fp6_mul_by_nonres_(x.c1);
    c3 = fp6_neg_(c3);
    c3 = fp6_add_(x.c0, c3);
    Fp6_ c2 = fp6_mul_(x.c0, x.c1);
    c0 = fp6_mul_(c0, c3);
    c0 = fp6_add_(c0, c2);
    Fp6_ r1 = fp6_double_(c2);
    c2 = fp6_mul_by_nonres_(c2);
    Fp6_ r0 = fp6_add_(c0, c2);
    Fp12_ r; r.c0 = r0; r.c1 = r1;
    return r;
}

__device__ Fp12_ fp12_inv_(const Fp12_& x) {
    Fp6_ t0 = fp6_sqr_(x.c0);
    Fp6_ t1 = fp6_sqr_(x.c1);
    Fp6_ tmp = fp6_mul_by_nonres_(t1);
    t0 = fp6_sub_(t0, tmp);
    Fp6_ t0_inv = fp6_inv_(t0);
    Fp12_ r;
    r.c0 = fp6_mul_(x.c0, t0_inv);
    r.c1 = fp6_neg_(fp6_mul_(x.c1, t0_inv));
    return r;
}

__device__ Fp12_ fp12_mul_by_034_(const Fp12_& z, const Fp2& c0, const Fp2& c3, const Fp2& c4) {
    Fp6_ a = fp6_mul_by_fp2_(z.c0, c0);
    Fp6_ b = z.c1;
    b = fp6_mul_by_01_(b, c3, c4);

    Fp2 d0 = fp2_add_(c0, c3);
    Fp6_ d = fp6_add_(z.c0, z.c1);
    d = fp6_mul_by_01_(d, d0, c4);

    Fp6_ r1 = fp6_add_(a, b);
    r1 = fp6_neg_(r1);
    r1 = fp6_add_(r1, d);
    Fp6_ r0 = fp6_mul_by_nonres_(b);
    r0 = fp6_add_(r0, a);
    Fp12_ r; r.c0 = r0; r.c1 = r1;
    return r;
}

struct Fp12Sparse5 { Fp2 v00, v01, v02, v10, v11; };

__device__ Fp12Sparse5 fp12_mul_034_by_034_(
    const Fp2& d0, const Fp2& d3, const Fp2& d4,
    const Fp2& c0, const Fp2& c3, const Fp2& c4) {
    Fp2 x0 = fp2_mul_(c0, d0);
    Fp2 x3 = fp2_mul_(c3, d3);
    Fp2 x4 = fp2_mul_(c4, d4);

    Fp2 tmp = fp2_add_(c0, c4);
    Fp2 x04 = fp2_add_(d0, d4);
    x04 = fp2_mul_(x04, tmp);
    x04 = fp2_sub_(x04, x0);
    x04 = fp2_sub_(x04, x4);

    tmp = fp2_add_(c0, c3);
    Fp2 x03 = fp2_add_(d0, d3);
    x03 = fp2_mul_(x03, tmp);
    x03 = fp2_sub_(x03, x0);
    x03 = fp2_sub_(x03, x3);

    tmp = fp2_add_(c3, c4);
    Fp2 x34 = fp2_add_(d3, d4);
    x34 = fp2_mul_(x34, tmp);
    x34 = fp2_sub_(x34, x3);
    x34 = fp2_sub_(x34, x4);

    Fp2 z00 = fp2_mul_by_nonres_(x4);
    z00 = fp2_add_(z00, x0);
    Fp12Sparse5 r;
    r.v00 = z00; r.v01 = x3; r.v02 = x34; r.v10 = x03; r.v11 = x04;
    return r;
}

__device__ Fp12_ fp12_mul_by_01234_(const Fp12_& z, const Fp12Sparse5& x) {
    Fp6_ c0_part; c0_part.b0 = x.v00; c0_part.b1 = x.v01; c0_part.b2 = x.v02;
    Fp6_ c1_part; c1_part.b0 = x.v10; c1_part.b1 = x.v11; c1_part.b2 = fp2_zero_();

    Fp6_ a = fp6_add_(z.c0, z.c1);
    Fp6_ b = fp6_add_(c0_part, c1_part);
    a = fp6_mul_(a, b);

    b = fp6_mul_(z.c0, c0_part);
    Fp6_ c = fp6_mul_by_01_(z.c1, x.v10, x.v11);

    Fp6_ r1 = fp6_sub_(a, b);
    r1 = fp6_sub_(r1, c);

    Fp6_ r0 = fp6_mul_by_nonres_(c);
    r0 = fp6_add_(r0, b);

    Fp12_ r; r.c0 = r0; r.c1 = r1;
    return r;
}

// =============================================================================
// Frobenius operators on Fp12 (Algorithms 28-30, eprint 2010/354).
// =============================================================================

__device__ Fp2 mul_nr1_(const Fp2& x, const u64* nr_a0, const u64* nr_a1) {
    Fp2 nr;
    #pragma unroll
    for (int i = 0; i < 4; ++i) { nr.a0.limbs[i] = nr_a0[i]; nr.a1.limbs[i] = nr_a1[i]; }
    return fp2_mul_(x, nr);
}

__device__ Fp2 mul_nr2_(const Fp2& x, const u64* nr_scalar) {
    U256 s;
    #pragma unroll
    for (int i = 0; i < 4; ++i) s.limbs[i] = nr_scalar[i];
    Fp2 r; r.a0 = fp_mul(x.a0, s); r.a1 = fp_mul(x.a1, s);
    return r;
}

__device__ Fp12_ frobenius_(const Fp12_& x) {
    Fp2 t0 = fp2_conjugate_(x.c0.b0);
    Fp2 t1 = fp2_conjugate_(x.c0.b1);
    Fp2 t2 = fp2_conjugate_(x.c0.b2);
    Fp2 t3 = fp2_conjugate_(x.c1.b0);
    Fp2 t4 = fp2_conjugate_(x.c1.b1);
    Fp2 t5 = fp2_conjugate_(x.c1.b2);

    t1 = mul_nr1_(t1, K_NR1P2_A0, K_NR1P2_A1);
    t2 = mul_nr1_(t2, K_NR1P4_A0, K_NR1P4_A1);
    t3 = mul_nr1_(t3, K_NR1P1_A0, K_NR1P1_A1);
    t4 = mul_nr1_(t4, K_NR1P3_A0, K_NR1P3_A1);
    t5 = mul_nr1_(t5, K_NR1P5_A0, K_NR1P5_A1);

    Fp12_ z;
    z.c0.b0 = t0; z.c0.b1 = t1; z.c0.b2 = t2;
    z.c1.b0 = t3; z.c1.b1 = t4; z.c1.b2 = t5;
    return z;
}

__device__ Fp12_ frobenius_sq_(const Fp12_& x) {
    Fp12_ z;
    z.c0.b0 = x.c0.b0;
    z.c0.b1 = mul_nr2_(x.c0.b1, K_NR2P2);
    z.c0.b2 = mul_nr2_(x.c0.b2, K_NR2P4);
    z.c1.b0 = mul_nr2_(x.c1.b0, K_NR2P1);
    z.c1.b1 = mul_nr2_(x.c1.b1, K_NR2P3);
    z.c1.b2 = mul_nr2_(x.c1.b2, K_NR2P5);
    return z;
}

__device__ Fp12_ frobenius_cube_(const Fp12_& x) {
    Fp2 t0 = fp2_conjugate_(x.c0.b0);
    Fp2 t1 = fp2_conjugate_(x.c0.b1);
    Fp2 t2 = fp2_conjugate_(x.c0.b2);
    Fp2 t3 = fp2_conjugate_(x.c1.b0);
    Fp2 t4 = fp2_conjugate_(x.c1.b1);
    Fp2 t5 = fp2_conjugate_(x.c1.b2);

    t1 = mul_nr1_(t1, K_NR3P2_A0, K_NR3P2_A1);
    t2 = mul_nr1_(t2, K_NR3P4_A0, K_NR3P4_A1);
    t3 = mul_nr1_(t3, K_NR3P1_A0, K_NR3P1_A1);
    t4 = mul_nr1_(t4, K_NR3P3_A0, K_NR3P3_A1);
    t5 = mul_nr1_(t5, K_NR3P5_A0, K_NR3P5_A1);

    Fp12_ z;
    z.c0.b0 = t0; z.c0.b1 = t1; z.c0.b2 = t2;
    z.c1.b0 = t3; z.c1.b1 = t4; z.c1.b2 = t5;
    return z;
}

// =============================================================================
// Granger-Scott cyclotomic squaring (eprint 2009/565 §3.2).
// =============================================================================

__device__ Fp12_ cyclotomic_sqr_(const Fp12_& x) {
    Fp2 t0 = fp2_sqr_(x.c1.b1);
    Fp2 t1 = fp2_sqr_(x.c0.b0);
    Fp2 t6 = fp2_sub_(fp2_sub_(fp2_sqr_(fp2_add_(x.c1.b1, x.c0.b0)), t0), t1);
    Fp2 t2 = fp2_sqr_(x.c0.b2);
    Fp2 t3 = fp2_sqr_(x.c1.b0);
    Fp2 t7 = fp2_sub_(fp2_sub_(fp2_sqr_(fp2_add_(x.c0.b2, x.c1.b0)), t2), t3);
    Fp2 t4 = fp2_sqr_(x.c1.b2);
    Fp2 t5 = fp2_sqr_(x.c0.b1);
    Fp2 t8 = fp2_sub_(fp2_sub_(fp2_sqr_(fp2_add_(x.c1.b2, x.c0.b1)), t4), t5);
    t8 = fp2_mul_by_nonres_(t8);

    t0 = fp2_add_(fp2_mul_by_nonres_(t0), t1);
    t2 = fp2_add_(fp2_mul_by_nonres_(t2), t3);
    t4 = fp2_add_(fp2_mul_by_nonres_(t4), t5);

    Fp12_ z;
    z.c0.b0 = fp2_add_(fp2_double_(fp2_sub_(t0, x.c0.b0)), t0);
    z.c0.b1 = fp2_add_(fp2_double_(fp2_sub_(t2, x.c0.b1)), t2);
    z.c0.b2 = fp2_add_(fp2_double_(fp2_sub_(t4, x.c0.b2)), t4);
    z.c1.b0 = fp2_add_(fp2_double_(fp2_add_(t8, x.c1.b0)), t8);
    z.c1.b1 = fp2_add_(fp2_double_(fp2_add_(t6, x.c1.b1)), t6);
    z.c1.b2 = fp2_add_(fp2_double_(fp2_add_(t7, x.c1.b2)), t7);
    return z;
}

__device__ Fp12_ cyclotomic_n_sqr_(Fp12_ z, int n) {
    for (int i = 0; i < n; ++i) z = cyclotomic_sqr_(z);
    return z;
}

// =============================================================================
// Expt: x^t with t = 4965661367192848881 -- gnark addition chain.
// =============================================================================

__device__ Fp12_ expt_(const Fp12_& x) {
    Fp12_ t3 = cyclotomic_sqr_(x);
    Fp12_ t5 = cyclotomic_sqr_(t3);
    Fp12_ result = cyclotomic_sqr_(t5);
    Fp12_ t0 = cyclotomic_sqr_(result);
    Fp12_ t2 = fp12_mul_(x, t0);
    t0 = fp12_mul_(t3, t2);
    Fp12_ t1 = fp12_mul_(x, t0);
    Fp12_ t4 = fp12_mul_(result, t2);
    Fp12_ t6 = cyclotomic_sqr_(t2);
    t1 = fp12_mul_(t0, t1);
    t0 = fp12_mul_(t3, t1);

    t6 = cyclotomic_n_sqr_(t6, 6);
    t5 = fp12_mul_(t5, t6);
    t5 = fp12_mul_(t4, t5);

    t5 = cyclotomic_n_sqr_(t5, 7);
    t4 = fp12_mul_(t4, t5);

    t4 = cyclotomic_n_sqr_(t4, 8);
    t4 = fp12_mul_(t0, t4);
    t3 = fp12_mul_(t3, t4);

    t3 = cyclotomic_n_sqr_(t3, 6);
    t2 = fp12_mul_(t2, t3);

    t2 = cyclotomic_n_sqr_(t2, 8);
    t2 = fp12_mul_(t0, t2);

    t2 = cyclotomic_n_sqr_(t2, 6);
    t2 = fp12_mul_(t0, t2);

    t2 = cyclotomic_n_sqr_(t2, 10);
    t1 = fp12_mul_(t1, t2);

    t1 = cyclotomic_n_sqr_(t1, 6);
    t0 = fp12_mul_(t0, t1);
    return fp12_mul_(result, t0);
}

// =============================================================================
// G2 affine + projective ops + line evaluations.
// =============================================================================

__device__ G2Aff g2_neg_(const G2Aff& a) {
    G2Aff r; r.x = a.x; r.y = fp2_neg_(a.y); r.inf = a.inf;
    return r;
}

__device__ G2Proj g2_to_proj_(const G2Aff& a) {
    G2Proj p; p.x = a.x; p.y = a.y; p.z = fp2_one_();
    return p;
}

struct LineEval { Fp2 r0, r1, r2; };

__device__ U256 fp_halve_(const U256& v) {
    U256 r = v;
    if (r.limbs[0] & 1ULL) {
        U256 P_ = u256_load(K_P);
        U256 t;
        u64 c = add_256(r, P_, t);
        r = t;
        for (int i = 0; i < 3; ++i)
            r.limbs[i] = (r.limbs[i] >> 1) | (r.limbs[i+1] << 63);
        r.limbs[3] = (r.limbs[3] >> 1) | (c << 63);
    } else {
        for (int i = 0; i < 3; ++i)
            r.limbs[i] = (r.limbs[i] >> 1) | (r.limbs[i+1] << 63);
        r.limbs[3] >>= 1;
    }
    return r;
}

__device__ Fp2 fp2_halve_(const Fp2& x) {
    Fp2 r; r.a0 = fp_halve_(x.a0); r.a1 = fp_halve_(x.a1);
    return r;
}

__device__ Fp2 mul_b_twist_(const Fp2& x) {
    Fp2 res = fp2_mul_by_nonres_inv_(x);
    return fp2_add_(fp2_double_(res), res);
}

__device__ void g2_double_step_(G2Proj& p, LineEval& ev) {
    Fp2 A = fp2_mul_(p.x, p.y);
    A = fp2_halve_(A);
    Fp2 B = fp2_sqr_(p.y);
    Fp2 C = fp2_sqr_(p.z);
    Fp2 D = fp2_double_(C);
    D = fp2_add_(D, C);
    Fp2 E = mul_b_twist_(D);
    Fp2 F = fp2_double_(E);
    F = fp2_add_(F, E);
    Fp2 G = fp2_add_(B, F);
    G = fp2_halve_(G);
    Fp2 H = fp2_add_(p.y, p.z);
    H = fp2_sqr_(H);
    Fp2 t1 = fp2_add_(B, C);
    H = fp2_sub_(H, t1);
    Fp2 I = fp2_sub_(E, B);
    Fp2 J = fp2_sqr_(p.x);
    Fp2 EE = fp2_sqr_(E);
    Fp2 K = fp2_double_(EE);
    K = fp2_add_(K, EE);

    p.x = fp2_sub_(B, F);
    p.x = fp2_mul_(p.x, A);
    p.y = fp2_sqr_(G);
    p.y = fp2_sub_(p.y, K);
    p.z = fp2_mul_(B, H);

    ev.r0 = fp2_neg_(H);
    ev.r1 = fp2_double_(J);
    ev.r1 = fp2_add_(ev.r1, J);
    ev.r2 = I;
}

__device__ void g2_add_mixed_step_(G2Proj& p, LineEval& ev, const G2Aff& a) {
    Fp2 Y2Z1 = fp2_mul_(a.y, p.z);
    Fp2 O = fp2_sub_(p.y, Y2Z1);
    Fp2 X2Z1 = fp2_mul_(a.x, p.z);
    Fp2 L = fp2_sub_(p.x, X2Z1);
    Fp2 C = fp2_sqr_(O);
    Fp2 D = fp2_sqr_(L);
    Fp2 E = fp2_mul_(L, D);
    Fp2 F = fp2_mul_(p.z, C);
    Fp2 G = fp2_mul_(p.x, D);
    Fp2 t0 = fp2_double_(G);
    Fp2 H = fp2_add_(E, F);
    H = fp2_sub_(H, t0);
    Fp2 t1 = fp2_mul_(p.y, E);

    p.x = fp2_mul_(L, H);
    p.y = fp2_sub_(G, H);
    p.y = fp2_mul_(p.y, O);
    p.y = fp2_sub_(p.y, t1);
    p.z = fp2_mul_(E, p.z);

    Fp2 t2 = fp2_mul_(L, a.y);
    Fp2 J = fp2_mul_(a.x, O);
    J = fp2_sub_(J, t2);

    ev.r0 = L;
    ev.r1 = fp2_neg_(O);
    ev.r2 = J;
}

__device__ void g2_line_compute_(const G2Proj& p, LineEval& ev, const G2Aff& a) {
    Fp2 Y2Z1 = fp2_mul_(a.y, p.z);
    Fp2 O = fp2_sub_(p.y, Y2Z1);
    Fp2 X2Z1 = fp2_mul_(a.x, p.z);
    Fp2 L = fp2_sub_(p.x, X2Z1);
    Fp2 t2 = fp2_mul_(L, a.y);
    Fp2 J = fp2_mul_(a.x, O);
    J = fp2_sub_(J, t2);

    ev.r0 = L;
    ev.r1 = fp2_neg_(O);
    ev.r2 = J;
}

// =============================================================================
// 6x+2 NAF loop counter (matches CPU bn254_pairing.cpp:kLoopCounter).
// =============================================================================

__constant__ signed char K_LOOP_NAF[65] = {
    0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0,
    0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0, 0, 1, 1,
    1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1,
    1, 0, 0, -1, 0, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, 1,
    1
};

// =============================================================================
// Single-pair Miller loop. Multi-pair composition is host-side (tree-reduce
// of per-pair Fp12, single final-exp at end).
// =============================================================================

__device__ Fp12_ miller_one_(const G1Aff& P, const G2Aff& Q) {
    if (P.inf || Q.inf) return fp12_one_();

    G2Proj qProj = g2_to_proj_(Q);
    G2Aff qNeg  = g2_neg_(Q);

    Fp12_ result = fp12_one_();
    LineEval l1, l2;

    // Skip i=64 (LoopCounter[64] == 0 and result still 1).
    g2_double_step_(qProj, l1);
    result.c0.b0 = fp2_mul_by_fp_(l1.r0, P.y);
    result.c1.b0 = fp2_mul_by_fp_(l1.r1, P.x);
    result.c1.b1 = l1.r2;

    // i=63 (LoopCounter[63] == -1).
    result = fp12_sqr_(result);
    g2_line_compute_(qProj, l2, qNeg);
    l2.r0 = fp2_mul_by_fp_(l2.r0, P.y);
    l2.r1 = fp2_mul_by_fp_(l2.r1, P.x);
    g2_add_mixed_step_(qProj, l1, Q);
    l1.r0 = fp2_mul_by_fp_(l1.r0, P.y);
    l1.r1 = fp2_mul_by_fp_(l1.r1, P.x);
    Fp12Sparse5 prod = fp12_mul_034_by_034_(l1.r0, l1.r1, l1.r2, l2.r0, l2.r1, l2.r2);
    result = fp12_mul_by_01234_(result, prod);

    // i=62 .. 0
    for (int i = 65 - 4; i >= 0; --i) {
        result = fp12_sqr_(result);
        g2_double_step_(qProj, l1);
        l1.r0 = fp2_mul_by_fp_(l1.r0, P.y);
        l1.r1 = fp2_mul_by_fp_(l1.r1, P.x);

        signed char lc = K_LOOP_NAF[i];
        if (lc == 1) {
            g2_add_mixed_step_(qProj, l2, Q);
            l2.r0 = fp2_mul_by_fp_(l2.r0, P.y);
            l2.r1 = fp2_mul_by_fp_(l2.r1, P.x);
            prod = fp12_mul_034_by_034_(l1.r0, l1.r1, l1.r2, l2.r0, l2.r1, l2.r2);
            result = fp12_mul_by_01234_(result, prod);
        } else if (lc == -1) {
            g2_add_mixed_step_(qProj, l2, qNeg);
            l2.r0 = fp2_mul_by_fp_(l2.r0, P.y);
            l2.r1 = fp2_mul_by_fp_(l2.r1, P.x);
            prod = fp12_mul_034_by_034_(l1.r0, l1.r1, l1.r2, l2.r0, l2.r1, l2.r2);
            result = fp12_mul_by_01234_(result, prod);
        } else {
            result = fp12_mul_by_034_(result, l1.r0, l1.r1, l1.r2);
        }
    }

    // Final 6x+2 + Frobenius corrections: Q1 = pi(Q), Q2 = -pi^2(Q).
    G2Aff Q1, Q2;
    Fp2 q1x = fp2_conjugate_(Q.x);
    Fp2 q1y = fp2_conjugate_(Q.y);
    Fp2 nr_p2;
    #pragma unroll
    for (int i = 0; i < 4; ++i) { nr_p2.a0.limbs[i] = K_NR1P2_A0[i]; nr_p2.a1.limbs[i] = K_NR1P2_A1[i]; }
    Fp2 nr_p3;
    #pragma unroll
    for (int i = 0; i < 4; ++i) { nr_p3.a0.limbs[i] = K_NR1P3_A0[i]; nr_p3.a1.limbs[i] = K_NR1P3_A1[i]; }
    Q1.x = fp2_mul_(q1x, nr_p2);
    Q1.y = fp2_mul_(q1y, nr_p3);
    Q1.inf = 0;

    U256 nr2_p2;
    #pragma unroll
    for (int i = 0; i < 4; ++i) nr2_p2.limbs[i] = K_NR2P2[i];
    U256 nr2_p3;
    #pragma unroll
    for (int i = 0; i < 4; ++i) nr2_p3.limbs[i] = K_NR2P3[i];
    Fp2 q2x; q2x.a0 = fp_mul(Q.x.a0, nr2_p2); q2x.a1 = fp_mul(Q.x.a1, nr2_p2);
    Fp2 q2y; q2y.a0 = fp_mul(Q.y.a0, nr2_p3); q2y.a1 = fp_mul(Q.y.a1, nr2_p3);
    Q2.x = q2x; Q2.y = fp2_neg_(q2y); Q2.inf = 0;

    g2_add_mixed_step_(qProj, l2, Q1);
    l2.r0 = fp2_mul_by_fp_(l2.r0, P.y);
    l2.r1 = fp2_mul_by_fp_(l2.r1, P.x);
    g2_line_compute_(qProj, l1, Q2);
    l1.r0 = fp2_mul_by_fp_(l1.r0, P.y);
    l1.r1 = fp2_mul_by_fp_(l1.r1, P.x);
    prod = fp12_mul_034_by_034_(l1.r0, l1.r1, l1.r2, l2.r0, l2.r1, l2.r2);
    result = fp12_mul_by_01234_(result, prod);

    return result;
}

// =============================================================================
// Final exponentiation -- Fuentes-Castaneda (Duquesne-Ghammam eprint 2015/192).
// =============================================================================

__device__ Fp12_ final_exp_(const Fp12_& z) {
    Fp12_ result = z;
    Fp12_ t0 = fp12_conjugate_(result);
    result = fp12_inv_(result);
    t0 = fp12_mul_(t0, result);
    result = frobenius_sq_(t0);
    result = fp12_mul_(result, t0);

    if (fp12_is_one_(result)) return result;

    Fp12_ t[5];
    t[0] = expt_(result);
    t[0] = fp12_conjugate_(t[0]);
    t[0] = cyclotomic_sqr_(t[0]);
    t[1] = cyclotomic_sqr_(t[0]);
    t[1] = fp12_mul_(t[0], t[1]);
    t[2] = expt_(t[1]);
    t[2] = fp12_conjugate_(t[2]);
    t[3] = fp12_conjugate_(t[1]);
    t[1] = fp12_mul_(t[2], t[3]);
    t[3] = cyclotomic_sqr_(t[2]);
    t[4] = expt_(t[3]);
    t[4] = fp12_mul_(t[1], t[4]);
    t[3] = fp12_mul_(t[0], t[4]);
    t[0] = fp12_mul_(t[2], t[4]);
    t[0] = fp12_mul_(result, t[0]);
    t[2] = frobenius_(t[3]);
    t[0] = fp12_mul_(t[2], t[0]);
    t[2] = frobenius_sq_(t[4]);
    t[0] = fp12_mul_(t[2], t[0]);
    t[2] = fp12_conjugate_(result);
    t[2] = fp12_mul_(t[2], t[3]);
    t[2] = frobenius_cube_(t[2]);
    t[0] = fp12_mul_(t[2], t[0]);

    return t[0];
}

// =============================================================================
// I/O helpers
// =============================================================================

__device__ void load_fp2_(Fp2& out, const u64* p) {
    #pragma unroll
    for (int i = 0; i < 4; ++i) { out.a0.limbs[i] = p[i]; out.a1.limbs[i] = p[4+i]; }
}

__device__ void store_fp2_(u64* p, const Fp2& x) {
    #pragma unroll
    for (int i = 0; i < 4; ++i) { p[i] = x.a0.limbs[i]; p[4+i] = x.a1.limbs[i]; }
}

__device__ void load_g2_(G2Aff& out, const u64* p) {
    load_fp2_(out.x, p);
    load_fp2_(out.y, p + 8);
    out.inf = (int)p[16];
}

__device__ void store_fp12_(u64* p, const Fp12_& x) {
    store_fp2_(p +  0, x.c0.b0);
    store_fp2_(p +  8, x.c0.b1);
    store_fp2_(p + 16, x.c0.b2);
    store_fp2_(p + 24, x.c1.b0);
    store_fp2_(p + 32, x.c1.b1);
    store_fp2_(p + 40, x.c1.b2);
}

__device__ void load_fp12_(Fp12_& out, const u64* p) {
    load_fp2_(out.c0.b0, p +  0);
    load_fp2_(out.c0.b1, p +  8);
    load_fp2_(out.c0.b2, p + 16);
    load_fp2_(out.c1.b0, p + 24);
    load_fp2_(out.c1.b1, p + 32);
    load_fp2_(out.c1.b2, p + 40);
}

#endif  // KINET_BN254_PAIRING_CUH

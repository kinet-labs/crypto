// CUDA port of bls_fp2.metal — Fp2 = Fp[u]/(u^2 + 1).
// Layout matches blst_fp2 byte-for-byte.

#ifndef BLS_FP2_CUH
#define BLS_FP2_CUH

#include "bls_fp_ops.cuh"

struct Fp2 { uint384 c0, c1; };

__device__ __forceinline__ Fp2 fp2_add(Fp2 a, Fp2 b) {
    Fp2 r; r.c0 = fp_add(a.c0, b.c0); r.c1 = fp_add(a.c1, b.c1); return r;
}

__device__ __forceinline__ Fp2 fp2_sub(Fp2 a, Fp2 b) {
    Fp2 r; r.c0 = fp_sub(a.c0, b.c0); r.c1 = fp_sub(a.c1, b.c1); return r;
}

__device__ __forceinline__ Fp2 fp2_neg(Fp2 a) {
    Fp2 r; r.c0 = fp_neg(a.c0); r.c1 = fp_neg(a.c1); return r;
}

__device__ __forceinline__ Fp2 fp2_mul(Fp2 a, Fp2 b) {
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

__device__ __forceinline__ Fp2 fp2_sqr(Fp2 a) {
    uint384 ab  = fp_mul(a.c0, a.c1);
    uint384 sum = fp_add(a.c0, a.c1);
    uint384 dif = fp_sub(a.c0, a.c1);
    Fp2 r;
    r.c0 = fp_mul(sum, dif);
    r.c1 = fp_add(ab, ab);
    return r;
}

__device__ __forceinline__ Fp2 fp2_conj(Fp2 a) {
    Fp2 r; r.c0 = a.c0; r.c1 = fp_neg(a.c1); return r;
}

__device__ __forceinline__ Fp2 fp2_inv(Fp2 a) {
    uint384 t0 = fp_sqr(a.c0);
    uint384 t1 = fp_sqr(a.c1);
    uint384 norm = fp_add(t0, t1);
    uint384 ni = fp_inv(norm);
    Fp2 r;
    r.c0 = fp_mul(a.c0, ni);
    r.c1 = fp_neg(fp_mul(a.c1, ni));
    return r;
}

__device__ __forceinline__ Fp2 fp2_frobenius(Fp2 a, unsigned n) {
    return ((n & 1u) == 1u) ? fp2_conj(a) : a;
}

__device__ __forceinline__ Fp2 fp2_mul_by_1_plus_u(Fp2 a) {
    Fp2 r;
    r.c0 = fp_sub(a.c0, a.c1);
    r.c1 = fp_add(a.c0, a.c1);
    return r;
}

__device__ __forceinline__ bool fp2_is_zero(Fp2 a) {
    return u384_is_zero(a.c0) && u384_is_zero(a.c1);
}

__device__ __forceinline__ Fp2 fp2_one() {
    Fp2 r; r.c0 = BLS_R_dev(); r.c1 = ZERO384_dev(); return r;
}

__device__ __forceinline__ Fp2 fp2_zero() {
    Fp2 r; r.c0 = ZERO384_dev(); r.c1 = ZERO384_dev(); return r;
}

#endif // BLS_FP2_CUH

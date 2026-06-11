// CUDA port of bls_fp12.metal — Fp12 = Fp6[w] / (w^2 - v).
// Layout matches blst_fp12 byte-for-byte.

#ifndef BLS_FP12_CUH
#define BLS_FP12_CUH

#include "bls_fp6.cuh"

struct Fp12 { Fp6 c0, c1; };

__device__ __forceinline__ Fp12 fp12_add(Fp12 a, Fp12 b) {
    Fp12 r;
    r.c0 = fp6_add(a.c0, b.c0);
    r.c1 = fp6_add(a.c1, b.c1);
    return r;
}

__device__ __forceinline__ Fp12 fp12_sub(Fp12 a, Fp12 b) {
    Fp12 r;
    r.c0 = fp6_sub(a.c0, b.c0);
    r.c1 = fp6_sub(a.c1, b.c1);
    return r;
}

__device__ __forceinline__ Fp6 fp6_mul_by_v(Fp6 a) {
    Fp6 r;
    r.c0 = fp2_mul_by_1_plus_u(a.c2);
    r.c1 = a.c0;
    r.c2 = a.c1;
    return r;
}

__device__ __forceinline__ Fp12 fp12_mul(Fp12 a, Fp12 b) {
    Fp6 t0 = fp6_mul(a.c0, b.c0);
    Fp6 t1 = fp6_mul(a.c1, b.c1);

    Fp6 sa = fp6_add(a.c0, a.c1);
    Fp6 sb = fp6_add(b.c0, b.c1);
    Fp6 r1 = fp6_mul(sa, sb);
    r1 = fp6_sub(r1, t0);
    r1 = fp6_sub(r1, t1);

    Fp6 r0 = fp6_add(t0, fp6_mul_by_v(t1));

    Fp12 r; r.c0 = r0; r.c1 = r1; return r;
}

__device__ __forceinline__ Fp12 fp12_sqr(Fp12 a) {
    Fp6 t0 = fp6_add(a.c0, a.c1);
    Fp6 t1 = fp6_mul_by_v(a.c1);
    t1 = fp6_add(a.c0, t1);
    t0 = fp6_mul(t0, t1);

    Fp6 t2 = fp6_mul(a.c0, a.c1);

    Fp12 r;
    r.c1 = fp6_add(t2, t2);

    Fp6 r0 = fp6_sub(t0, t2);
    r0 = fp6_sub(r0, fp6_mul_by_v(t2));
    r.c0 = r0;
    return r;
}

__device__ __forceinline__ Fp12 fp12_conj(Fp12 a) {
    Fp12 r;
    r.c0 = a.c0;
    r.c1 = fp6_neg(a.c1);
    return r;
}

__device__ __forceinline__ Fp12 fp12_inv(Fp12 a) {
    Fp6 t0 = fp6_sqr(a.c0);
    Fp6 t1 = fp6_sqr(a.c1);
    t0 = fp6_sub(t0, fp6_mul_by_v(t1));
    Fp6 ti = fp6_inv(t0);

    Fp12 r;
    r.c0 = fp6_mul(a.c0, ti);
    r.c1 = fp6_mul(a.c1, ti);
    r.c1 = fp6_neg(r.c1);
    return r;
}

__device__ __forceinline__ void sqr_fp4(Fp2& r0, Fp2& r1, Fp2 a0, Fp2 a1) {
    Fp2 t0 = fp2_sqr(a0);
    Fp2 t1 = fp2_sqr(a1);
    Fp2 sum = fp2_add(a0, a1);

    r0 = fp2_add(fp2_mul_by_1_plus_u(t1), t0);

    r1 = fp2_sqr(sum);
    r1 = fp2_sub(r1, t0);
    r1 = fp2_sub(r1, t1);
}

__device__ __forceinline__ Fp12 fp12_cyclotomic_sqr(Fp12 a) {
    Fp2 t00, t01, t10, t11, t20, t21;
    sqr_fp4(t00, t01, a.c0.c0, a.c1.c1);
    sqr_fp4(t10, t11, a.c1.c0, a.c0.c2);
    sqr_fp4(t20, t21, a.c0.c1, a.c1.c2);

    Fp12 r;
    Fp2 tmp = fp2_sub(t00, a.c0.c0);
    r.c0.c0 = fp2_add(fp2_add(tmp, tmp), t00);

    tmp = fp2_sub(t10, a.c0.c1);
    r.c0.c1 = fp2_add(fp2_add(tmp, tmp), t10);

    tmp = fp2_sub(t20, a.c0.c2);
    r.c0.c2 = fp2_add(fp2_add(tmp, tmp), t20);

    tmp = fp2_mul_by_1_plus_u(t21);
    Fp2 add = fp2_add(tmp, a.c1.c0);
    r.c1.c0 = fp2_add(fp2_add(add, add), tmp);

    add = fp2_add(t01, a.c1.c1);
    r.c1.c1 = fp2_add(fp2_add(add, add), t01);

    add = fp2_add(t11, a.c1.c2);
    r.c1.c2 = fp2_add(fp2_add(add, add), t11);

    return r;
}

// Frobenius coefficients for Fp12 — verbatim from blst.
__device__ __forceinline__ static uint384 FP12_FROB_RE_N1_dev() {
    uint384 r = {{
        0x07089552B319D465ULL, 0xC6695F92B50A8313ULL, 0x97E83CCCD117228FULL,
        0xA35BAECAB2DC29EEULL, 0x1CE393EA5DAACE4DULL, 0x08F2220FB0FB66EBULL
    }}; return r;
}
__device__ __forceinline__ static uint384 FP12_FROB_IM_N1_dev() {
    uint384 r = {{
        0xB2F66AAD4CE5D646ULL, 0x5842A06BFC497CECULL, 0xCF4895D42599D394ULL,
        0xC11B9CBA40A8E8D0ULL, 0x2E3813CBE5A0DE89ULL, 0x110EEFDA88847FAFULL
    }}; return r;
}
__device__ __forceinline__ static uint384 FP12_FROB_RE_N2_dev() {
    uint384 r = {{
        0xECFB361B798DBA3AULL, 0xC100DDB891865A2CULL, 0x0EC08FF1232BDA8EULL,
        0xD5C13CC6F1CA4721ULL, 0x47222A47BF7B5C04ULL, 0x0110F184E51C5F59ULL
    }}; return r;
}
__device__ __forceinline__ static uint384 FP12_FROB_IM_N2_dev() {
    uint384 r = {{0,0,0,0,0,0}}; return r;
}
__device__ __forceinline__ static uint384 FP12_FROB_RE_N3_dev() {
    uint384 r = {{
        0x3E2F585DA55C9AD1ULL, 0x4294213D86C18183ULL, 0x382844C88B623732ULL,
        0x92AD2AFD19103E18ULL, 0x1D794E4FAC7CF0B9ULL, 0x0BD592FC7D825EC8ULL
    }}; return r;
}
__device__ __forceinline__ static uint384 FP12_FROB_IM_N3_dev() {
    uint384 r = {{
        0x7BCFA7A25AA30FDAULL, 0xDC17DEC12A927E7CULL, 0x2F088DD86B4EBEF1ULL,
        0xD1CA2087DA74D4A7ULL, 0x2DA2596696CEBC1DULL, 0x0E2B7EEDBBFD87D2ULL
    }}; return r;
}

__device__ __forceinline__ Fp12 fp12_frobenius(Fp12 a, unsigned n) {
    Fp6 r0 = fp6_frobenius(a.c0, n);
    Fp6 r1 = fp6_frobenius(a.c1, n);

    Fp2 coeff;
    if (n == 1u) {
        coeff.c0 = FP12_FROB_RE_N1_dev(); coeff.c1 = FP12_FROB_IM_N1_dev();
    } else if (n == 2u) {
        coeff.c0 = FP12_FROB_RE_N2_dev(); coeff.c1 = FP12_FROB_IM_N2_dev();
    } else {
        coeff.c0 = FP12_FROB_RE_N3_dev(); coeff.c1 = FP12_FROB_IM_N3_dev();
    }
    r1.c0 = fp2_mul(r1.c0, coeff);
    r1.c1 = fp2_mul(r1.c1, coeff);
    r1.c2 = fp2_mul(r1.c2, coeff);

    Fp12 r; r.c0 = r0; r.c1 = r1; return r;
}

__device__ __forceinline__ Fp12 fp12_one() {
    Fp2 zerop = fp2_zero();
    Fp2 onep  = fp2_one();
    Fp6 one6;  one6.c0  = onep;    one6.c1  = zerop;  one6.c2 = zerop;
    Fp6 zero6; zero6.c0 = zerop;   zero6.c1 = zerop;  zero6.c2 = zerop;
    Fp12 r; r.c0 = one6; r.c1 = zero6; return r;
}

#endif // BLS_FP12_CUH

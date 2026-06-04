// CUDA port of bls_fp6.metal — Fp6 = Fp2[v] / (v^3 - (u + 1)).
// Layout matches blst_fp6 byte-for-byte.

#ifndef BLS_FP6_CUH
#define BLS_FP6_CUH

#include "bls_fp2.cuh"

struct Fp6 { Fp2 c0, c1, c2; };

__device__ __forceinline__ Fp6 fp6_add(Fp6 a, Fp6 b) {
    Fp6 r;
    r.c0 = fp2_add(a.c0, b.c0);
    r.c1 = fp2_add(a.c1, b.c1);
    r.c2 = fp2_add(a.c2, b.c2);
    return r;
}

__device__ __forceinline__ Fp6 fp6_sub(Fp6 a, Fp6 b) {
    Fp6 r;
    r.c0 = fp2_sub(a.c0, b.c0);
    r.c1 = fp2_sub(a.c1, b.c1);
    r.c2 = fp2_sub(a.c2, b.c2);
    return r;
}

__device__ __forceinline__ Fp6 fp6_neg(Fp6 a) {
    Fp6 r;
    r.c0 = fp2_neg(a.c0);
    r.c1 = fp2_neg(a.c1);
    r.c2 = fp2_neg(a.c2);
    return r;
}

__device__ __forceinline__ Fp6 fp6_mul(Fp6 a, Fp6 b) {
    Fp2 t0 = fp2_mul(a.c0, b.c0);
    Fp2 t1 = fp2_mul(a.c1, b.c1);
    Fp2 t2 = fp2_mul(a.c2, b.c2);

    Fp2 sa12 = fp2_add(a.c1, a.c2);
    Fp2 sb12 = fp2_add(b.c1, b.c2);
    Fp2 r0 = fp2_mul(sa12, sb12);
    r0 = fp2_sub(r0, t1);
    r0 = fp2_sub(r0, t2);
    r0 = fp2_mul_by_1_plus_u(r0);
    r0 = fp2_add(r0, t0);

    Fp2 sa01 = fp2_add(a.c0, a.c1);
    Fp2 sb01 = fp2_add(b.c0, b.c1);
    Fp2 r1 = fp2_mul(sa01, sb01);
    r1 = fp2_sub(r1, t0);
    r1 = fp2_sub(r1, t1);
    r1 = fp2_add(r1, fp2_mul_by_1_plus_u(t2));

    Fp2 sa02 = fp2_add(a.c0, a.c2);
    Fp2 sb02 = fp2_add(b.c0, b.c2);
    Fp2 r2 = fp2_mul(sa02, sb02);
    r2 = fp2_sub(r2, t0);
    r2 = fp2_sub(r2, t2);
    r2 = fp2_add(r2, t1);

    Fp6 r; r.c0 = r0; r.c1 = r1; r.c2 = r2; return r;
}

__device__ __forceinline__ Fp6 fp6_sqr(Fp6 a) {
    Fp2 s0  = fp2_sqr(a.c0);
    Fp2 m01 = fp2_mul(a.c0, a.c1); m01 = fp2_add(m01, m01);
    Fp2 m12 = fp2_mul(a.c1, a.c2); m12 = fp2_add(m12, m12);
    Fp2 s2  = fp2_sqr(a.c2);

    Fp2 sum = fp2_add(fp2_add(a.c0, a.c1), a.c2);
    Fp2 r2  = fp2_sqr(sum);
    r2 = fp2_sub(r2, s0);
    r2 = fp2_sub(r2, s2);
    r2 = fp2_sub(r2, m01);
    r2 = fp2_sub(r2, m12);

    Fp2 r0 = fp2_mul_by_1_plus_u(m12);
    r0 = fp2_add(r0, s0);

    Fp2 r1 = fp2_mul_by_1_plus_u(s2);
    r1 = fp2_add(r1, m01);

    Fp6 r; r.c0 = r0; r.c1 = r1; r.c2 = r2; return r;
}

__device__ __forceinline__ Fp6 fp6_inv(Fp6 a) {
    Fp2 c0 = fp2_sqr(a.c0);
    Fp2 t  = fp2_mul(a.c1, a.c2);
    t = fp2_mul_by_1_plus_u(t);
    c0 = fp2_sub(c0, t);

    Fp2 c1 = fp2_sqr(a.c2);
    c1 = fp2_mul_by_1_plus_u(c1);
    Fp2 t01 = fp2_mul(a.c0, a.c1);
    c1 = fp2_sub(c1, t01);

    Fp2 c2 = fp2_sqr(a.c1);
    Fp2 t02 = fp2_mul(a.c0, a.c2);
    c2 = fp2_sub(c2, t02);

    Fp2 t1 = fp2_mul(c1, a.c2);
    Fp2 t2 = fp2_mul(c2, a.c1);
    Fp2 norm = fp2_add(t1, t2);
    norm = fp2_mul_by_1_plus_u(norm);
    norm = fp2_add(norm, fp2_mul(c0, a.c0));

    Fp2 ni = fp2_inv(norm);

    Fp6 r;
    r.c0 = fp2_mul(c0, ni);
    r.c1 = fp2_mul(c1, ni);
    r.c2 = fp2_mul(c2, ni);
    return r;
}

// Frobenius coefficients (Montgomery form), copied verbatim from Metal/blst.
__device__ __forceinline__ static uint384 FP6_FROB_C1_RE_N1_dev() {
    uint384 r = {{0,0,0,0,0,0}}; return r;
}
__device__ __forceinline__ static uint384 FP6_FROB_C1_IM_N1_dev() {
    uint384 r = {{
        0xCD03C9E48671F071ULL, 0x5DAB22461FCDA5D2ULL, 0x587042AFD3851B95ULL,
        0x8EB60EBE01BACB9EULL, 0x03F97D6E83D050D2ULL, 0x18F0206554638741ULL
    }}; return r;
}
__device__ __forceinline__ static uint384 FP6_FROB_C1_RE_N2_dev() {
    uint384 r = {{
        0x30F1361B798A64E8ULL, 0xF3B8DDAB7ECE5A2AULL, 0x16A8CA3AC61577F7ULL,
        0xC26A2FF874FD029BULL, 0x3636B76660701C6EULL, 0x051BA4AB241B6160ULL
    }}; return r;
}
__device__ __forceinline__ static uint384 FP6_FROB_C1_IM_N2_dev() {
    uint384 r = {{0,0,0,0,0,0}}; return r;
}
__device__ __forceinline__ static uint384 FP6_FROB_C1_RE_N3_dev() {
    uint384 r = {{0,0,0,0,0,0}}; return r;
}
__device__ __forceinline__ static uint384 FP6_FROB_C1_IM_N3_dev() {
    uint384 r = {{
        0x760900000002FFFDULL, 0xEBF4000BC40C0002ULL, 0x5F48985753C758BAULL,
        0x77CE585370525745ULL, 0x5C071A97A256EC6DULL, 0x15F65EC3FA80E493ULL
    }}; return r;
}
__device__ __forceinline__ static uint384 FP6_FROB_C2_N1_dev() {
    uint384 r = {{
        0x890DC9E4867545C3ULL, 0x2AF322533285A5D5ULL, 0x50880866309B7E2CULL,
        0xA20D1B8C7E881024ULL, 0x14E4F04FE2DB9068ULL, 0x14E56D3F1564853AULL
    }}; return r;
}
__device__ __forceinline__ static uint384 FP6_FROB_C2_N2_dev() {
    uint384 r = {{
        0xCD03C9E48671F071ULL, 0x5DAB22461FCDA5D2ULL, 0x587042AFD3851B95ULL,
        0x8EB60EBE01BACB9EULL, 0x03F97D6E83D050D2ULL, 0x18F0206554638741ULL
    }}; return r;
}
__device__ __forceinline__ static uint384 FP6_FROB_C2_N3_dev() {
    uint384 r = {{
        0x43F5FFFFFFFCAAAEULL, 0x32B7FFF2ED47FFFDULL, 0x07E83A49A2E99D69ULL,
        0xECA8F3318332BB7AULL, 0xEF148D1EA0F4C069ULL, 0x040AB3263EFF0206ULL
    }}; return r;
}

__device__ __forceinline__ Fp6 fp6_frobenius(Fp6 a, unsigned n) {
    Fp2 r0 = fp2_frobenius(a.c0, n);
    Fp2 r1 = fp2_frobenius(a.c1, n);
    Fp2 r2 = fp2_frobenius(a.c2, n);

    Fp2 c1; uint384 c2_real;
    if (n == 1u) {
        c1.c0 = FP6_FROB_C1_RE_N1_dev(); c1.c1 = FP6_FROB_C1_IM_N1_dev();
        c2_real = FP6_FROB_C2_N1_dev();
    } else if (n == 2u) {
        c1.c0 = FP6_FROB_C1_RE_N2_dev(); c1.c1 = FP6_FROB_C1_IM_N2_dev();
        c2_real = FP6_FROB_C2_N2_dev();
    } else {
        c1.c0 = FP6_FROB_C1_RE_N3_dev(); c1.c1 = FP6_FROB_C1_IM_N3_dev();
        c2_real = FP6_FROB_C2_N3_dev();
    }

    r1 = fp2_mul(r1, c1);
    r2.c0 = fp_mul(r2.c0, c2_real);
    r2.c1 = fp_mul(r2.c1, c2_real);

    Fp6 r; r.c0 = r0; r.c1 = r1; r.c2 = r2; return r;
}

#endif // BLS_FP6_CUH

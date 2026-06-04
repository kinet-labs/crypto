// Fp6 = Fp2[v] / (v^3 - (u + 1)) for BLS12-381.
// Layout: struct Fp6 { Fp2 c0, c1, c2; }  ==  blst_fp6 { blst_fp2 fp2[3]; } byte-equal.
// Element  c0 + c1 v + c2 v^2  with v^3 = u + 1.
//
// Algorithms mirror blst src/fp12_tower.c (reference path).
//
// mul (schoolbook with v^3 = u+1 reduction):
//   t0 = a0 b0,  t1 = a1 b1,  t2 = a2 b2
//   r0 = ((a1+a2)(b1+b2) - t1 - t2)(u+1) + t0
//   r1 = (a0+a1)(b0+b1) - t0 - t1 + t2(u+1)
//   r2 = (a0+a2)(b0+b2) - t0 - t2 + t1
//
// sqr (Chung-Hasan SQR3):
//   s0 = a0^2,  s2 = a2^2
//   m01 = 2 a0 a1,  m12 = 2 a1 a2
//   r0 = m12 (u+1) + s0
//   r1 = s2 (u+1) + m01
//   r2 = (a0+a1+a2)^2 - s0 - s2 - m01 - m12
//
// inv (Itoh-Tsujii):  see blst inverse_fp6.
//
// Frobenius coefficients hardcoded from blst src/fp12_tower.c lines 675-695,
// already in Montgomery form.

#ifndef BLS_FP6_INLINES
#define BLS_FP6_INLINES

#define BLS_FP2_NO_KERNELS
#include "bls_fp2.metal"
#undef BLS_FP2_NO_KERNELS

struct Fp6 { Fp2 c0, c1, c2; };

inline Fp6 fp6_add(Fp6 a, Fp6 b) {
    Fp6 r;
    r.c0 = fp2_add(a.c0, b.c0);
    r.c1 = fp2_add(a.c1, b.c1);
    r.c2 = fp2_add(a.c2, b.c2);
    return r;
}

inline Fp6 fp6_sub(Fp6 a, Fp6 b) {
    Fp6 r;
    r.c0 = fp2_sub(a.c0, b.c0);
    r.c1 = fp2_sub(a.c1, b.c1);
    r.c2 = fp2_sub(a.c2, b.c2);
    return r;
}

inline Fp6 fp6_neg(Fp6 a) {
    Fp6 r;
    r.c0 = fp2_neg(a.c0);
    r.c1 = fp2_neg(a.c1);
    r.c2 = fp2_neg(a.c2);
    return r;
}

inline Fp6 fp6_mul(Fp6 a, Fp6 b) {
    Fp2 t0 = fp2_mul(a.c0, b.c0);
    Fp2 t1 = fp2_mul(a.c1, b.c1);
    Fp2 t2 = fp2_mul(a.c2, b.c2);

    // r0 = ((a1 + a2)(b1 + b2) - t1 - t2)(u+1) + t0
    Fp2 sa12 = fp2_add(a.c1, a.c2);
    Fp2 sb12 = fp2_add(b.c1, b.c2);
    Fp2 r0 = fp2_mul(sa12, sb12);
    r0 = fp2_sub(r0, t1);
    r0 = fp2_sub(r0, t2);
    r0 = fp2_mul_by_1_plus_u(r0);
    r0 = fp2_add(r0, t0);

    // r1 = (a0 + a1)(b0 + b1) - t0 - t1 + t2(u+1)
    Fp2 sa01 = fp2_add(a.c0, a.c1);
    Fp2 sb01 = fp2_add(b.c0, b.c1);
    Fp2 r1 = fp2_mul(sa01, sb01);
    r1 = fp2_sub(r1, t0);
    r1 = fp2_sub(r1, t1);
    r1 = fp2_add(r1, fp2_mul_by_1_plus_u(t2));

    // r2 = (a0 + a2)(b0 + b2) - t0 - t2 + t1
    Fp2 sa02 = fp2_add(a.c0, a.c2);
    Fp2 sb02 = fp2_add(b.c0, b.c2);
    Fp2 r2 = fp2_mul(sa02, sb02);
    r2 = fp2_sub(r2, t0);
    r2 = fp2_sub(r2, t2);
    r2 = fp2_add(r2, t1);

    Fp6 r; r.c0 = r0; r.c1 = r1; r.c2 = r2; return r;
}

inline Fp6 fp6_sqr(Fp6 a) {
    Fp2 s0  = fp2_sqr(a.c0);
    Fp2 m01 = fp2_mul(a.c0, a.c1); m01 = fp2_add(m01, m01);
    Fp2 m12 = fp2_mul(a.c1, a.c2); m12 = fp2_add(m12, m12);
    Fp2 s2  = fp2_sqr(a.c2);

    // r2 = (a0 + a1 + a2)^2 - s0 - s2 - m01 - m12
    Fp2 sum = fp2_add(fp2_add(a.c0, a.c1), a.c2);
    Fp2 r2  = fp2_sqr(sum);
    r2 = fp2_sub(r2, s0);
    r2 = fp2_sub(r2, s2);
    r2 = fp2_sub(r2, m01);
    r2 = fp2_sub(r2, m12);

    // r0 = m12 (u+1) + s0
    Fp2 r0 = fp2_mul_by_1_plus_u(m12);
    r0 = fp2_add(r0, s0);

    // r1 = s2 (u+1) + m01
    Fp2 r1 = fp2_mul_by_1_plus_u(s2);
    r1 = fp2_add(r1, m01);

    Fp6 r; r.c0 = r0; r.c1 = r1; r.c2 = r2; return r;
}

inline Fp6 fp6_inv(Fp6 a) {
    // c0 = a0^2 - (a1 a2)(u+1)
    Fp2 c0 = fp2_sqr(a.c0);
    Fp2 t  = fp2_mul(a.c1, a.c2);
    t = fp2_mul_by_1_plus_u(t);
    c0 = fp2_sub(c0, t);

    // c1 = a2^2 (u+1) - a0 a1
    Fp2 c1 = fp2_sqr(a.c2);
    c1 = fp2_mul_by_1_plus_u(c1);
    Fp2 t01 = fp2_mul(a.c0, a.c1);
    c1 = fp2_sub(c1, t01);

    // c2 = a1^2 - a0 a2
    Fp2 c2 = fp2_sqr(a.c1);
    Fp2 t02 = fp2_mul(a.c0, a.c2);
    c2 = fp2_sub(c2, t02);

    // norm = (a2 c1 + a1 c2)(u+1) + a0 c0
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

// Frobenius coefficients (Montgomery form), from blst src/fp12_tower.c lines 675-695.
//
//   FP6_FROB_C1[n-1] = (u + 1)^((p^n - 1) / 3)         in Fp2 (real, imag)
//   FP6_FROB_C2[n-1] = (u + 1)^((2 p^n - 2) / 3)       in Fp  (real)
//
// Only n in {1, 2, 3} supported (sufficient for BLS12-381 Miller loop).

constant uint384 FP6_FROB_C1_RE_N1 = {{0,0,0,0,0,0}};
constant uint384 FP6_FROB_C1_IM_N1 = {{
    0xCD03C9E48671F071UL, 0x5DAB22461FCDA5D2UL, 0x587042AFD3851B95UL,
    0x8EB60EBE01BACB9EUL, 0x03F97D6E83D050D2UL, 0x18F0206554638741UL
}};

constant uint384 FP6_FROB_C1_RE_N2 = {{
    0x30F1361B798A64E8UL, 0xF3B8DDAB7ECE5A2AUL, 0x16A8CA3AC61577F7UL,
    0xC26A2FF874FD029BUL, 0x3636B76660701C6EUL, 0x051BA4AB241B6160UL
}};
constant uint384 FP6_FROB_C1_IM_N2 = {{0,0,0,0,0,0}};

constant uint384 FP6_FROB_C1_RE_N3 = {{0,0,0,0,0,0}};
// blst comment: "implied ONE_MONT_P at index 0"  =>  imag part = R mod p (= 1 in Mont)
constant uint384 FP6_FROB_C1_IM_N3 = {{
    0x760900000002FFFDUL, 0xEBF4000BC40C0002UL, 0x5F48985753C758BAUL,
    0x77CE585370525745UL, 0x5C071A97A256EC6DUL, 0x15F65EC3FA80E493UL
}};

constant uint384 FP6_FROB_C2_N1 = {{
    0x890DC9E4867545C3UL, 0x2AF322533285A5D5UL, 0x50880866309B7E2CUL,
    0xA20D1B8C7E881024UL, 0x14E4F04FE2DB9068UL, 0x14E56D3F1564853AUL
}};
constant uint384 FP6_FROB_C2_N2 = {{
    0xCD03C9E48671F071UL, 0x5DAB22461FCDA5D2UL, 0x587042AFD3851B95UL,
    0x8EB60EBE01BACB9EUL, 0x03F97D6E83D050D2UL, 0x18F0206554638741UL
}};
constant uint384 FP6_FROB_C2_N3 = {{
    0x43F5FFFFFFFCAAAEUL, 0x32B7FFF2ED47FFFDUL, 0x07E83A49A2E99D69UL,
    0xECA8F3318332BB7AUL, 0xEF148D1EA0F4C069UL, 0x040AB3263EFF0206UL
}};

inline Fp6 fp6_frobenius(Fp6 a, uint n) {
    Fp2 r0 = fp2_frobenius(a.c0, n);
    Fp2 r1 = fp2_frobenius(a.c1, n);
    Fp2 r2 = fp2_frobenius(a.c2, n);

    Fp2 c1; uint384 c2_real;
    if (n == 1u) {
        c1.c0 = FP6_FROB_C1_RE_N1; c1.c1 = FP6_FROB_C1_IM_N1;
        c2_real = FP6_FROB_C2_N1;
    } else if (n == 2u) {
        c1.c0 = FP6_FROB_C1_RE_N2; c1.c1 = FP6_FROB_C1_IM_N2;
        c2_real = FP6_FROB_C2_N2;
    } else {
        c1.c0 = FP6_FROB_C1_RE_N3; c1.c1 = FP6_FROB_C1_IM_N3;
        c2_real = FP6_FROB_C2_N3;
    }

    r1 = fp2_mul(r1, c1);
    // c2 coefficient is pure-Fp; multiply both real and imaginary components.
    r2.c0 = fp_mul(r2.c0, c2_real);
    r2.c1 = fp_mul(r2.c1, c2_real);

    Fp6 r; r.c0 = r0; r.c1 = r1; r.c2 = r2; return r;
}

#endif // BLS_FP6_INLINES

// =============================================================================
// Kernels — buffer element size = 288 bytes (sizeof(Fp6) = 3 * 96).
// =============================================================================

#ifndef BLS_FP6_NO_KERNELS

kernel void k_fp6_add(
    device const Fp6* a [[buffer(0)]],
    device const Fp6* b [[buffer(1)]],
    device       Fp6* out [[buffer(2)]],
    constant uint& n [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp6_add(a[tid], b[tid]);
}

kernel void k_fp6_sub(
    device const Fp6* a [[buffer(0)]],
    device const Fp6* b [[buffer(1)]],
    device       Fp6* out [[buffer(2)]],
    constant uint& n [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp6_sub(a[tid], b[tid]);
}

kernel void k_fp6_mul(
    device const Fp6* a [[buffer(0)]],
    device const Fp6* b [[buffer(1)]],
    device       Fp6* out [[buffer(2)]],
    constant uint& n [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp6_mul(a[tid], b[tid]);
}

kernel void k_fp6_sqr(
    device const Fp6* a [[buffer(0)]],
    device       Fp6* out [[buffer(1)]],
    constant uint& n [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp6_sqr(a[tid]);
}

kernel void k_fp6_inv(
    device const Fp6* a [[buffer(0)]],
    device       Fp6* out [[buffer(1)]],
    constant uint& n [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp6_inv(a[tid]);
}

#endif // BLS_FP6_NO_KERNELS

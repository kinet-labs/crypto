// CUDA port of bls_miller.metal — BLS12-381 optimal-ate Miller loop.
// Same kernel split as Metal (host orchestrates dispatches).

#ifndef BLS_MILLER_CUH
#define BLS_MILLER_CUH

#include "bls_fp12.cuh"
#include "bls_g2.cuh"

struct P1Aff { uint384 X, Y; };
struct Line { Fp2 x, y, z; };
struct LineBuf { Fp2 x, y, z; };

struct MillerIn {
    P2Aff Q;
    P1Aff P;
};

__device__ static Line line_dbl_dev(P2& T, P2 Q) {
    Fp2 A  = fp2_sqr(Q.X);
    Fp2 B  = fp2_sqr(Q.Y);
    Fp2 ZZ = fp2_sqr(Q.Z);
    Fp2 C  = fp2_sqr(B);

    Fp2 D = fp2_add(Q.X, B);
    D = fp2_sqr(D);
    D = fp2_sub(D, A);
    D = fp2_sub(D, C);
    D = fp2_add(D, D);

    Fp2 E = fp2_add(A, A);
    E = fp2_add(E, A);

    Fp2 F = fp2_sqr(E);

    Fp2 line0 = fp2_add(E, Q.X);

    Fp2 Tx = fp2_sub(F, D);
    Tx     = fp2_sub(Tx, D);

    Fp2 Tz = fp2_add(Q.Y, Q.Z);
    Tz     = fp2_sqr(Tz);
    Tz     = fp2_sub(Tz, B);
    Tz     = fp2_sub(Tz, ZZ);

    Fp2 C8 = fp2_add(C, C);
    C8 = fp2_add(C8, C8);
    C8 = fp2_add(C8, C8);

    Fp2 Ty = fp2_sub(D, Tx);
    Ty     = fp2_mul(Ty, E);
    Ty     = fp2_sub(Ty, C8);

    line0 = fp2_sqr(line0);
    line0 = fp2_sub(line0, A);
    line0 = fp2_sub(line0, F);
    Fp2 B4 = fp2_add(B, B);
    B4 = fp2_add(B4, B4);
    line0 = fp2_sub(line0, B4);

    Fp2 line1 = fp2_mul(E, ZZ);
    Fp2 line2 = fp2_mul(Tz, ZZ);

    T.X = Tx; T.Y = Ty; T.Z = Tz;

    Line L; L.x = line0; L.y = line1; L.z = line2;
    return L;
}

__device__ static Line line_add_dev(P2& T, P2 R, P2Aff Q) {
    Fp2 Z1Z1 = fp2_sqr(R.Z);
    Fp2 U2   = fp2_mul(Q.X, Z1Z1);

    Fp2 S2   = fp2_mul(Q.Y, R.Z);
    S2       = fp2_mul(S2, Z1Z1);

    Fp2 H = fp2_sub(U2, R.X);

    Fp2 HH = fp2_sqr(H);
    Fp2 I  = fp2_add(HH, HH);
    I      = fp2_add(I, I);

    Fp2 J  = fp2_mul(H, I);

    Fp2 r  = fp2_sub(S2, R.Y);
    r      = fp2_add(r, r);

    Fp2 V  = fp2_mul(R.X, I);

    Fp2 Tx = fp2_sqr(r);
    Tx     = fp2_sub(Tx, J);
    Tx     = fp2_sub(Tx, V);
    Tx     = fp2_sub(Tx, V);

    Fp2 Jy = fp2_mul(J, R.Y);
    Fp2 Ty = fp2_sub(V, Tx);
    Ty     = fp2_mul(Ty, r);
    Ty     = fp2_sub(Ty, Jy);
    Ty     = fp2_sub(Ty, Jy);

    Fp2 Tz = fp2_add(R.Z, H);
    Tz     = fp2_sqr(Tz);
    Tz     = fp2_sub(Tz, Z1Z1);
    Tz     = fp2_sub(Tz, HH);

    Fp2 lineI = fp2_mul(r, Q.X);
    Fp2 lineJ = fp2_mul(Q.Y, Tz);
    lineI     = fp2_sub(lineI, lineJ);
    Fp2 line0 = fp2_add(lineI, lineI);

    T.X = Tx; T.Y = Ty; T.Z = Tz;

    Line L; L.x = line0; L.y = r; L.z = Tz;
    return L;
}

__device__ __forceinline__ Line line_by_Px2_dev(Line L, uint384 px_neg2, uint384 py_2) {
    L.y.c0 = fp_mul(L.y.c0, px_neg2);
    L.y.c1 = fp_mul(L.y.c1, px_neg2);
    L.z.c0 = fp_mul(L.z.c0, py_2);
    L.z.c1 = fp_mul(L.z.c1, py_2);
    return L;
}

__device__ __forceinline__ Fp6 fp6_mul_by_xy0_dev(Fp6 a, Fp2 b0, Fp2 b1) {
    Fp2 t0 = fp2_mul(a.c0, b0);
    Fp2 t1 = fp2_mul(a.c1, b1);

    Fp2 t3 = fp2_mul(a.c2, b1);
    t3     = fp2_mul_by_1_plus_u(t3);

    Fp2 t4 = fp2_add(a.c0, a.c1);
    Fp2 t5 = fp2_add(b0, b1);
    Fp2 r1 = fp2_mul(t4, t5);
    r1     = fp2_sub(r1, t0);
    r1     = fp2_sub(r1, t1);

    Fp2 r2 = fp2_mul(a.c2, b0);
    r2     = fp2_add(r2, t1);

    Fp2 r0 = fp2_add(t3, t0);

    Fp6 r; r.c0 = r0; r.c1 = r1; r.c2 = r2; return r;
}

__device__ __forceinline__ Fp6 fp6_mul_by_0y0_dev(Fp6 a, Fp2 b) {
    Fp2 t      = fp2_mul(a.c2, b);
    Fp6 r;
    r.c2       = fp2_mul(a.c1, b);
    r.c1       = fp2_mul(a.c0, b);
    r.c0       = fp2_mul_by_1_plus_u(t);
    return r;
}

__device__ static Fp12 fp12_mul_by_xy00z0_dev(Fp12 a, Line L) {
    Fp6 t0 = fp6_mul_by_xy0_dev(a.c0, L.x, L.y);
    Fp6 t1 = fp6_mul_by_0y0_dev(a.c1, L.z);

    Fp2 b1_alt = fp2_add(L.y, L.z);
    Fp6 sum    = fp6_add(a.c0, a.c1);
    Fp6 r1     = fp6_mul_by_xy0_dev(sum, L.x, b1_alt);
    r1         = fp6_sub(r1, t0);
    r1         = fp6_sub(r1, t1);

    Fp6 t1v;
    t1v.c0 = fp2_mul_by_1_plus_u(t1.c2);
    t1v.c1 = t1.c0;
    t1v.c2 = t1.c1;
    Fp6 r0 = fp6_add(t0, t1v);

    Fp12 r; r.c0 = r0; r.c1 = r1; return r;
}

__device__ __forceinline__ Fp12 unpack_initial_line_dev(Line L) {
    Fp12 ret;
    ret.c0.c0 = L.x;
    ret.c0.c1 = L.y;
    ret.c0.c2 = fp2_zero();
    ret.c1.c0 = fp2_zero();
    ret.c1.c1 = L.z;
    ret.c1.c2 = fp2_zero();
    return ret;
}

#endif // BLS_MILLER_CUH

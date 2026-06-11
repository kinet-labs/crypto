// CUDA port of bls_g2.metal — G2 = E'(Fp2). Layouts byte-equal blst.

#ifndef BLS_G2_CUH
#define BLS_G2_CUH

#include "bls_fp2.cuh"

struct P2    { Fp2 X, Y, Z; };
struct P2Aff { Fp2 X, Y;    };

__device__ __forceinline__ P2 p2_jac_add(P2 p1, P2 p2) {
    bool p1inf = fp2_is_zero(p1.Z);
    Fp2 Z1Z1 = fp2_sqr(p1.Z);

    Fp2 pZ = fp2_mul(Z1Z1, p1.Z);
    pZ     = fp2_mul(pZ, p2.Y);

    bool p2inf = fp2_is_zero(p2.Z);
    Fp2 Z2Z2 = fp2_sqr(p2.Z);

    Fp2 S1 = fp2_mul(Z2Z2, p2.Z);
    S1     = fp2_mul(S1, p1.Y);

    pZ = fp2_sub(pZ, S1);
    pZ = fp2_add(pZ, pZ);

    Fp2 U1 = fp2_mul(p1.X, Z2Z2);
    Fp2 H  = fp2_mul(p2.X, Z1Z1);
    H      = fp2_sub(H, U1);

    Fp2 I = fp2_add(H, H);
    I     = fp2_sqr(I);

    Fp2 J = fp2_mul(H, I);
    S1    = fp2_mul(S1, J);

    Fp2 V = fp2_mul(U1, I);

    Fp2 pX = fp2_sqr(pZ);
    pX = fp2_sub(pX, J);
    pX = fp2_sub(pX, V);
    pX = fp2_sub(pX, V);

    Fp2 pY = fp2_sub(V, pX);
    pY     = fp2_mul(pY, pZ);
    pY     = fp2_sub(pY, S1);
    pY     = fp2_sub(pY, S1);

    pZ = fp2_add(p1.Z, p2.Z);
    pZ = fp2_sqr(pZ);
    pZ = fp2_sub(pZ, Z1Z1);
    pZ = fp2_sub(pZ, Z2Z2);
    pZ = fp2_mul(pZ, H);

    P2 p3; p3.X = pX; p3.Y = pY; p3.Z = pZ;

    if (p2inf) p3 = p1;
    if (p1inf) p3 = p2;
    return p3;
}

__device__ __forceinline__ P2 p2_jac_dbl(P2 p1) {
    Fp2 A = fp2_sqr(p1.X);
    Fp2 B = fp2_sqr(p1.Y);
    Fp2 C = fp2_sqr(B);

    B = fp2_add(B, p1.X);
    B = fp2_sqr(B);
    B = fp2_sub(B, A);
    B = fp2_sub(B, C);
    B = fp2_add(B, B);

    Fp2 A3 = fp2_add(A, A);
    A3     = fp2_add(A3, A);

    Fp2 pX = fp2_sqr(A3);
    pX = fp2_sub(pX, B);
    pX = fp2_sub(pX, B);

    Fp2 pZ = fp2_add(p1.Z, p1.Z);
    pZ     = fp2_mul(pZ, p1.Y);

    Fp2 C8 = fp2_add(C, C);
    C8 = fp2_add(C8, C8);
    C8 = fp2_add(C8, C8);

    Fp2 pY = fp2_sub(B, pX);
    pY     = fp2_mul(pY, A3);
    pY     = fp2_sub(pY, C8);

    P2 p3; p3.X = pX; p3.Y = pY; p3.Z = pZ;
    return p3;
}

__device__ __forceinline__ P2 p2_mixed_add(P2 p1, P2Aff p2) {
    bool p1inf = fp2_is_zero(p1.Z);
    Fp2 Z1Z1 = fp2_sqr(p1.Z);

    Fp2 pZ = fp2_mul(Z1Z1, p1.Z);
    pZ     = fp2_mul(pZ, p2.Y);

    bool p2inf = fp2_is_zero(p2.X) && fp2_is_zero(p2.Y);

    Fp2 H = fp2_mul(p2.X, Z1Z1);
    H     = fp2_sub(H, p1.X);

    Fp2 HH = fp2_sqr(H);
    Fp2 I  = fp2_add(HH, HH);
    I      = fp2_add(I, I);

    Fp2 pY_v = fp2_mul(p1.X, I);
    Fp2 J    = fp2_mul(H, I);
    Fp2 Iy   = fp2_mul(J, p1.Y);

    pZ = fp2_sub(pZ, p1.Y);
    pZ = fp2_add(pZ, pZ);

    Fp2 pX = fp2_sqr(pZ);
    pX = fp2_sub(pX, J);
    pX = fp2_sub(pX, pY_v);
    pX = fp2_sub(pX, pY_v);

    Fp2 pY = fp2_sub(pY_v, pX);
    pY     = fp2_mul(pY, pZ);
    pY     = fp2_sub(pY, Iy);
    pY     = fp2_sub(pY, Iy);

    pZ = fp2_add(p1.Z, H);
    pZ = fp2_sqr(pZ);
    pZ = fp2_sub(pZ, Z1Z1);
    pZ = fp2_sub(pZ, HH);

    P2 p3; p3.X = pX; p3.Y = pY; p3.Z = pZ;

    if (p1inf) {
        p3.X = p2.X;
        p3.Y = p2.Y;
        p3.Z = fp2_one();
    }
    if (p2inf) p3 = p1;
    return p3;
}

__device__ __forceinline__ P2Aff p2_to_affine(P2 p) {
    P2Aff a;
    if (fp2_is_zero(p.Z)) {
        a.X = fp2_zero();
        a.Y = fp2_zero();
        return a;
    }
    Fp2 Zi   = fp2_inv(p.Z);
    Fp2 Zi2  = fp2_sqr(Zi);
    Fp2 Zi3  = fp2_mul(Zi2, Zi);
    a.X = fp2_mul(p.X, Zi2);
    a.Y = fp2_mul(p.Y, Zi3);
    return a;
}

__device__ __forceinline__ P2Aff p2_scalar_mult(P2 base, const unsigned char* scalar, unsigned nbits) {
    P2 R; R.X = fp2_zero(); R.Y = fp2_zero(); R.Z = fp2_zero();

    bool started = false;
    for (int i = (int)nbits - 1; i >= 0; i--) {
        unsigned char byte = scalar[i >> 3];
        unsigned bit = (unsigned)((byte >> (i & 7)) & 1u);
        if (started) R = p2_jac_dbl(R);
        if (bit) {
            if (started) {
                R = p2_jac_add(R, base);
            } else {
                R = base;
                started = true;
            }
        }
    }
    return p2_to_affine(R);
}

#endif // BLS_G2_CUH

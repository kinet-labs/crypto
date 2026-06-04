// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// G2 = E'(Fp2) for BLS12-381  (twist curve  y^2 = x^3 + 4(u+1)).
// Layouts:
//   struct P2     { Fp2 X, Y, Z; }   ==  blst_p2 / POINTonE2          (288 B)
//   struct P2Aff  { Fp2 X, Y;     }  ==  blst_p2_affine                (192 B)
// Bytes match blst exactly so a memcpy round-trips.
//
// Algorithms mirror blst src/ec_ops.h:
//   POINT_ADD_IMPL          -> p2_jac_add        (Jacobian + Jacobian)
//   POINT_DOUBLE_IMPL_A0    -> p2_jac_dbl        (a4 = 0 since BLS curve has a=0)
//   POINT_ADD_AFFINE_IMPL   -> p2_mixed_add      (Jacobian + affine)
//
// Scalar multiplication mirrors a left-to-right binary double-and-add.
// blst uses a 5-bit window with Booth recoding internally; rather than try to
// byte-match a Jacobian representation produced by Booth-window arithmetic,
// the kernel converts its result to AFFINE form and the test compares against
// blst's affine output. Affine encodings are unique for a given group element
// so byte-equality is preserved across algorithmic choice.
//
// Curve parameter:  a = 0,  b' = 4(u+1)  (twist).  All ops below are correct
// only because a = 0 (POINT_DOUBLE_IMPL_A0, POINT_DADD_IMPL with a4=NULL path).

#ifndef BLS_G2_INLINES
#define BLS_G2_INLINES

#define BLS_FP2_NO_KERNELS
#include "bls_fp2.metal"
#undef BLS_FP2_NO_KERNELS

struct P2    { Fp2 X, Y, Z; };
struct P2Aff { Fp2 X, Y;    };

inline bool fp2_is_zero(Fp2 a) {
    return u384_is_zero(a.c0) && u384_is_zero(a.c1);
}

// 1 in Fp2 (Montgomery): { c0 = R, c1 = 0 }.
inline Fp2 fp2_one() {
    Fp2 r; r.c0 = BLS_R; r.c1 = ZERO384; return r;
}

inline Fp2 fp2_zero() {
    Fp2 r; r.c0 = ZERO384; r.c1 = ZERO384; return r;
}

// Mirrors blst POINT_ADD_IMPL(POINTonE2, 384x, fp2). Handles either input at
// infinity (Z == 0). Does NOT handle the doubling case (H == 0); for safety we
// route through the d-add at the test level by ensuring random P != Q.
inline P2 p2_jac_add(P2 p1, P2 p2) {
    bool p1inf = fp2_is_zero(p1.Z);
    Fp2 Z1Z1 = fp2_sqr(p1.Z);

    Fp2 pZ = fp2_mul(Z1Z1, p1.Z);    // Z1*Z1Z1
    pZ     = fp2_mul(pZ, p2.Y);      // S2 = Y2*Z1*Z1Z1

    bool p2inf = fp2_is_zero(p2.Z);
    Fp2 Z2Z2 = fp2_sqr(p2.Z);

    Fp2 S1 = fp2_mul(Z2Z2, p2.Z);    // Z2*Z2Z2
    S1     = fp2_mul(S1, p1.Y);      // S1 = Y1*Z2*Z2Z2

    pZ = fp2_sub(pZ, S1);            // S2-S1
    pZ = fp2_add(pZ, pZ);            // r = 2*(S2-S1)

    Fp2 U1 = fp2_mul(p1.X, Z2Z2);    // U1 = X1*Z2Z2
    Fp2 H  = fp2_mul(p2.X, Z1Z1);    // U2 = X2*Z1Z1
    H      = fp2_sub(H, U1);         // H = U2-U1

    Fp2 I = fp2_add(H, H);           // 2*H
    I     = fp2_sqr(I);              // I = (2*H)^2

    Fp2 J = fp2_mul(H, I);           // J = H*I
    S1    = fp2_mul(S1, J);          // S1*J

    Fp2 V = fp2_mul(U1, I);          // V = U1*I

    Fp2 pX = fp2_sqr(pZ);            // r^2
    pX = fp2_sub(pX, J);             // r^2-J
    pX = fp2_sub(pX, V);
    pX = fp2_sub(pX, V);             // X3 = r^2-J-2*V

    Fp2 pY = fp2_sub(V, pX);         // V-X3
    pY     = fp2_mul(pY, pZ);        // r*(V-X3)
    pY     = fp2_sub(pY, S1);
    pY     = fp2_sub(pY, S1);        // Y3 = r*(V-X3)-2*S1*J

    pZ = fp2_add(p1.Z, p2.Z);        // Z1+Z2
    pZ = fp2_sqr(pZ);
    pZ = fp2_sub(pZ, Z1Z1);
    pZ = fp2_sub(pZ, Z2Z2);          // (Z1+Z2)^2-Z1Z1-Z2Z2
    pZ = fp2_mul(pZ, H);             // Z3 = (...)*H

    P2 p3; p3.X = pX; p3.Y = pY; p3.Z = pZ;

    if (p2inf) p3 = p1;
    if (p1inf) p3 = p2;
    return p3;
}

// Mirrors POINT_DOUBLE_IMPL_A0(POINTonE2, 384x, fp2). a = 0 for BLS12-381.
inline P2 p2_jac_dbl(P2 p1) {
    Fp2 A = fp2_sqr(p1.X);             // A = X1^2
    Fp2 B = fp2_sqr(p1.Y);             // B = Y1^2
    Fp2 C = fp2_sqr(B);                // C = B^2

    B = fp2_add(B, p1.X);              // X1+B
    B = fp2_sqr(B);                    // (X1+B)^2
    B = fp2_sub(B, A);
    B = fp2_sub(B, C);
    B = fp2_add(B, B);                 // D = 2*((X1+B)^2-A-C)

    // mul_by_3:  3*A = A + 2A
    Fp2 A3 = fp2_add(A, A);
    A3     = fp2_add(A3, A);           // E = 3*A

    Fp2 pX = fp2_sqr(A3);              // F = E^2
    pX = fp2_sub(pX, B);
    pX = fp2_sub(pX, B);               // X3 = F-2*D

    Fp2 pZ = fp2_add(p1.Z, p1.Z);      // 2*Z1
    pZ     = fp2_mul(pZ, p1.Y);        // Z3 = 2*Z1*Y1

    // mul_by_8:  8*C = ((C<<1)<<1)<<1
    Fp2 C8 = fp2_add(C, C);
    C8 = fp2_add(C8, C8);
    C8 = fp2_add(C8, C8);              // 8*C

    Fp2 pY = fp2_sub(B, pX);           // D-X3
    pY     = fp2_mul(pY, A3);          // E*(D-X3)
    pY     = fp2_sub(pY, C8);          // Y3 = E*(D-X3)-8*C

    P2 p3; p3.X = pX; p3.Y = pY; p3.Z = pZ;
    return p3;
}

// Mirrors POINT_ADD_AFFINE_IMPL(POINTonE2, 384x, fp2, BLS12_381_Rx.p2).
// |p1| at infinity encoded as Z==0; |p2| at infinity encoded as X==Y==0.
inline P2 p2_mixed_add(P2 p1, P2Aff p2) {
    bool p1inf = fp2_is_zero(p1.Z);
    Fp2 Z1Z1 = fp2_sqr(p1.Z);

    Fp2 pZ = fp2_mul(Z1Z1, p1.Z);       // Z1*Z1Z1
    pZ     = fp2_mul(pZ, p2.Y);         // S2 = Y2*Z1*Z1Z1

    bool p2inf = fp2_is_zero(p2.X) && fp2_is_zero(p2.Y);

    Fp2 H = fp2_mul(p2.X, Z1Z1);        // U2 = X2*Z1Z1
    H     = fp2_sub(H, p1.X);           // H = U2-X1

    Fp2 HH = fp2_sqr(H);                // HH = H^2
    Fp2 I  = fp2_add(HH, HH);
    I      = fp2_add(I, I);             // I = 4*HH

    Fp2 pY_v = fp2_mul(p1.X, I);        // V = X1*I
    Fp2 J    = fp2_mul(H, I);           // J = H*I
    Fp2 Iy   = fp2_mul(J, p1.Y);        // Y1*J

    pZ = fp2_sub(pZ, p1.Y);             // S2-Y1
    pZ = fp2_add(pZ, pZ);               // r = 2*(S2-Y1)

    Fp2 pX = fp2_sqr(pZ);               // r^2
    pX = fp2_sub(pX, J);
    pX = fp2_sub(pX, pY_v);
    pX = fp2_sub(pX, pY_v);             // X3 = r^2-J-2*V

    Fp2 pY = fp2_sub(pY_v, pX);         // V-X3
    pY     = fp2_mul(pY, pZ);           // r*(V-X3)
    pY     = fp2_sub(pY, Iy);
    pY     = fp2_sub(pY, Iy);           // Y3 = r*(V-X3)-2*Y1*J

    pZ = fp2_add(p1.Z, H);              // Z1+H
    pZ = fp2_sqr(pZ);
    pZ = fp2_sub(pZ, Z1Z1);
    pZ = fp2_sub(pZ, HH);               // Z3 = (Z1+H)^2-Z1Z1-HH

    P2 p3; p3.X = pX; p3.Y = pY; p3.Z = pZ;

    if (p1inf) {
        // p3 = p2 promoted to Jacobian (Z = 1)
        p3.X = p2.X;
        p3.Y = p2.Y;
        p3.Z = fp2_one();
    }
    if (p2inf) p3 = p1;
    return p3;
}

// Convert Jacobian -> affine.  Mirrors blst POINTonE2_from_Jacobian:
//   X_aff = X / Z^2,  Y_aff = Y / Z^3.   Z = 0 -> infinity (X=Y=0).
inline P2Aff p2_to_affine(P2 p) {
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

// Left-to-right binary scalar multiplication using the Jacobian add/dbl above.
// scalar is 32 little-endian bytes (matches blst's `byte *scalar` API
// when nbits = 256). bit_len caps how many bits of the scalar are processed
// and is provided by the caller (matches blst's `nbits` parameter).
//
// Output is converted to AFFINE for byte-equality comparison against blst,
// because blst's internal w=5 Booth recoding produces a different Jacobian
// representation that nevertheless decodes to the same affine point.
inline P2Aff p2_scalar_mult(P2 base, device const uchar* scalar, uint nbits) {
    // Jacobian zero (point at infinity)
    P2 R; R.X = fp2_zero(); R.Y = fp2_zero(); R.Z = fp2_zero();

    // Process bits MSB -> LSB.  Skip leading zeros so R stays at infinity until
    // the first set bit, at which point R becomes 2*infinity = infinity, then
    // the next "if bit" path handles initialization via mixed-zero add.
    bool started = false;
    for (int i = (int)nbits - 1; i >= 0; i--) {
        uchar byte = scalar[i >> 3];
        uint bit = (uint)((byte >> (i & 7)) & 1u);
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

#endif // BLS_G2_INLINES

// =============================================================================
// Kernels  —  P2 buffers are 288 B (3 * 96 B), P2Aff are 192 B (2 * 96 B).
// =============================================================================

#ifndef BLS_G2_NO_KERNELS

kernel void k_p2_jac_add(
    device const P2* a    [[buffer(0)]],
    device const P2* b    [[buffer(1)]],
    device       P2* out  [[buffer(2)]],
    constant uint& n      [[buffer(3)]],
    uint tid              [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = p2_jac_add(a[tid], b[tid]);
}

kernel void k_p2_jac_dbl(
    device const P2* a    [[buffer(0)]],
    device       P2* out  [[buffer(1)]],
    constant uint& n      [[buffer(2)]],
    uint tid              [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = p2_jac_dbl(a[tid]);
}

kernel void k_p2_mixed_add(
    device const P2*    a    [[buffer(0)]],
    device const P2Aff* b    [[buffer(1)]],
    device       P2*    out  [[buffer(2)]],
    constant uint& n         [[buffer(3)]],
    uint tid                 [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = p2_mixed_add(a[tid], b[tid]);
}

// Scalar mult: input layout per element
//   bytes [0..288)    : P2 base
//   bytes [288..320)  : 32 little-endian bytes scalar
// Output: P2Aff (192 bytes per element).
struct P2ScalarIn {
    P2    base;
    uchar scalar[32];
};

kernel void k_p2_scalar_mult(
    device const P2ScalarIn* in   [[buffer(0)]],
    device       P2Aff*      out  [[buffer(1)]],
    constant uint& n              [[buffer(2)]],
    constant uint& nbits          [[buffer(3)]],
    uint tid                      [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = p2_scalar_mult(in[tid].base, in[tid].scalar, nbits);
}

#endif // BLS_G2_NO_KERNELS

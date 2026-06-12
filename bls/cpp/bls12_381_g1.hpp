// First-party G1 elliptic curve arithmetic for BLS12-381.
//
//   y^2 = x^3 + 4    over Fp(p)   with  a = 0,  b = 4
//
// Same short-Weierstrass form as bn254 G1 (only the curve constant b
// differs), so the Bernstein-Lange Jacobian formulas
// efl/jacobian-0/{dbl-2009-l, add-2007-bl} apply unchanged.
//
// All field elements are stored in Montgomery form throughout.  Affine point
// (x, y) with x,y in Montgomery form.  Jacobian point (X, Y, Z) with the
// usual relation x = X/Z^2, y = Y/Z^3.
//
// The MSM caller (gpukit/curve_traits/bls12_381_g1_first_party_traits.h)
// uses g1_add / g1_double directly; g1_scalar_mul is included for
// completeness and for the Pippenger oracle in the test harness.
//
// Self-contained -- only depends on bls12_381_fp.hpp.

#pragma once

#include "bls12_381_fp.hpp"

namespace kinet::crypto::bls12_381 {

struct G1Affine {
    U384 x;
    U384 y;
    bool infinity;
};

struct G1Jac {
    U384 X;
    U384 Y;
    U384 Z;
    bool infinity;
};

inline G1Jac g1_jac_zero() noexcept {
    G1Jac r;
    r.X = U384{};
    r.Y = U384{};
    r.Z = U384{};
    r.infinity = true;
    return r;
}

inline G1Jac g1_to_jac(const G1Affine& p) noexcept {
    if (p.infinity) return g1_jac_zero();
    G1Jac r;
    r.X = p.x;
    r.Y = p.y;
    r.Z = R_FP;  // 1 in Montgomery form
    r.infinity = false;
    return r;
}

inline G1Affine g1_to_affine(const G1Jac& p) noexcept {
    G1Affine a;
    if (p.infinity || p.Z.is_zero()) {
        a.x = U384{};
        a.y = U384{};
        a.infinity = true;
        return a;
    }
    U384 z_inv  = fp_inv(p.Z);
    U384 z_inv2 = fp_sqr(z_inv);
    U384 z_inv3 = fp_mul(z_inv2, z_inv);
    a.x = fp_mul(p.X, z_inv2);
    a.y = fp_mul(p.Y, z_inv3);
    a.infinity = false;
    return a;
}

// Bernstein-Lange dbl-2009-l.  a = 0 short-Weierstrass.
inline G1Jac g1_double(const G1Jac& p) noexcept {
    if (p.infinity) return p;
    if (p.Y.is_zero()) return g1_jac_zero();

    U384 A = fp_sqr(p.X);
    U384 B = fp_sqr(p.Y);
    U384 C = fp_sqr(B);

    U384 X_plus_B = fp_add(p.X, B);
    U384 D = fp_sub(fp_sqr(X_plus_B), A);
    D = fp_sub(D, C);
    D = fp_add(D, D);

    U384 E = fp_add(A, A);
    E = fp_add(E, A);
    U384 F = fp_sqr(E);

    U384 two_D = fp_add(D, D);
    U384 X3 = fp_sub(F, two_D);

    U384 D_minus_X3 = fp_sub(D, X3);
    U384 eight_C = fp_add(C, C);
    eight_C = fp_add(eight_C, eight_C);
    eight_C = fp_add(eight_C, eight_C);
    U384 Y3 = fp_sub(fp_mul(E, D_minus_X3), eight_C);

    U384 Z3 = fp_mul(p.Y, p.Z);
    Z3 = fp_add(Z3, Z3);

    G1Jac r;
    r.X = X3;
    r.Y = Y3;
    r.Z = Z3;
    r.infinity = false;
    return r;
}

// Bernstein-Lange add-2007-bl.
inline G1Jac g1_add(const G1Jac& a, const G1Jac& b) noexcept {
    if (a.infinity) return b;
    if (b.infinity) return a;

    U384 Z1Z1 = fp_sqr(a.Z);
    U384 Z2Z2 = fp_sqr(b.Z);
    U384 U1 = fp_mul(a.X, Z2Z2);
    U384 U2 = fp_mul(b.X, Z1Z1);
    U384 S1 = fp_mul(fp_mul(a.Y, b.Z), Z2Z2);
    U384 S2 = fp_mul(fp_mul(b.Y, a.Z), Z1Z1);

    U384 H = fp_sub(U2, U1);
    if (H.is_zero()) {
        if (S1 == S2) return g1_double(a);
        return g1_jac_zero();
    }

    U384 two_H = fp_add(H, H);
    U384 I = fp_sqr(two_H);
    U384 J = fp_mul(H, I);

    U384 r_ = fp_sub(S2, S1);
    r_ = fp_add(r_, r_);

    U384 V = fp_mul(U1, I);

    U384 X3 = fp_sub(fp_sub(fp_sqr(r_), J), fp_add(V, V));
    U384 Y3 = fp_sub(fp_mul(r_, fp_sub(V, X3)),
                     fp_mul(fp_add(S1, S1), J));
    U384 Z3 = fp_sub(fp_sub(fp_sqr(fp_add(a.Z, b.Z)), Z1Z1), Z2Z2);
    Z3 = fp_mul(Z3, H);

    G1Jac out;
    out.X = X3;
    out.Y = Y3;
    out.Z = Z3;
    out.infinity = false;
    return out;
}

inline void cmov(G1Jac& dst, const G1Jac& src, u64 cond) noexcept {
    const u64 mask = (u64)0 - (cond & 1ULL);
    for (int i = 0; i < 6; ++i) {
        dst.X.limbs[i] ^= mask & (dst.X.limbs[i] ^ src.X.limbs[i]);
        dst.Y.limbs[i] ^= mask & (dst.Y.limbs[i] ^ src.Y.limbs[i]);
        dst.Z.limbs[i] ^= mask & (dst.Z.limbs[i] ^ src.Z.limbs[i]);
    }
    const bool inf = (cond & 1ULL) ? src.infinity : dst.infinity;
    dst.infinity = inf;
}

// Constant-time scalar multiplication using a Montgomery ladder over the
// 256-bit scalar window.  Used by the test oracle to compute random points
// (k * G) and to provide a single-scalar reference for the Pippenger MSM
// against which the multi_pippenger dispatcher is compared.
//
// The scalar k is supplied as 4 LE u64 limbs (packed into a 256-bit window
// of U384 -- the upper 2 limbs are ignored).
inline G1Jac g1_scalar_mul_256(const G1Affine& p, const u64 k_limbs[4]) noexcept {
    if (p.infinity) return g1_jac_zero();

    G1Jac R0 = g1_jac_zero();
    G1Jac R1 = g1_to_jac(p);

    for (int i = 255; i >= 0; --i) {
        const u64 bit = ((k_limbs[i >> 6] >> (i & 63)) & 1ULL);

        G1Jac sum  = g1_add(R0, R1);
        G1Jac dbl0 = g1_double(R0);
        G1Jac dbl1 = g1_double(R1);

        G1Jac next_R0 = dbl0;
        cmov(next_R0, sum,  bit);
        G1Jac next_R1 = sum;
        cmov(next_R1, dbl1, bit);

        R0 = next_R0;
        R1 = next_R1;
    }
    return R0;
}

inline bool g1_is_on_curve(const G1Affine& p) noexcept {
    if (p.infinity) return true;
    U384 lhs = fp_sqr(p.y);
    U384 rhs = fp_mul(fp_sqr(p.x), p.x);
    rhs = fp_add(rhs, fp_four());
    return lhs == rhs;
}

// BLS12-381 G1 generator (canonical IETF / EIP-2537 coordinates).
inline G1Affine g1_generator() noexcept {
    static const uint8_t Gx_be[48] = {
        0x17, 0xF1, 0xD3, 0xA7, 0x31, 0x97, 0xD7, 0x94,
        0x26, 0x95, 0x63, 0x8C, 0x4F, 0xA9, 0xAC, 0x0F,
        0xC3, 0x68, 0x8C, 0x4F, 0x97, 0x74, 0xB9, 0x05,
        0xA1, 0x4E, 0x3A, 0x3F, 0x17, 0x1B, 0xAC, 0x58,
        0x6C, 0x55, 0xE8, 0x3F, 0xF9, 0x7A, 0x1A, 0xEF,
        0xFB, 0x3A, 0xF0, 0x0A, 0xDB, 0x22, 0xC6, 0xBB};
    static const uint8_t Gy_be[48] = {
        0x08, 0xB3, 0xF4, 0x81, 0xE3, 0xAA, 0xA0, 0xF1,
        0xA0, 0x9E, 0x30, 0xED, 0x74, 0x1D, 0x8A, 0xE4,
        0xFC, 0xF5, 0xE0, 0x95, 0xD5, 0xD0, 0x0A, 0xF6,
        0x00, 0xDB, 0x18, 0xCB, 0x2C, 0x04, 0xB3, 0xED,
        0xD0, 0x3C, 0xC7, 0x44, 0xA2, 0x88, 0x8A, 0xE4,
        0x0C, 0xAA, 0x23, 0x29, 0x46, 0xC5, 0xE7, 0xE1};
    G1Affine G;
    G.x = to_mont_fp(U384::from_be48(Gx_be));
    G.y = to_mont_fp(U384::from_be48(Gy_be));
    G.infinity = false;
    return G;
}

}  // namespace kinet::crypto::bls12_381

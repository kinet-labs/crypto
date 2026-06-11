// First-party G2 elliptic curve arithmetic for bn254 (alt_bn128) over Fp2.
// G2 is the sextic twist E': y^2 = x^3 + 3 / (9 + u). All field elements are
// in Montgomery form throughout.
//
// Coordinate systems used here:
//   * Affine (x, y, infinity)
//   * Jacobian (X, Y, Z) with x = X/Z^2, y = Y/Z^3 (used for scalar mul)
//   * Homogeneous projective (x, y, z) with x = X/Z, y = Y/Z (used in the
//     Miller-loop line evaluations -- see bn254_pairing.hpp).
//
// Scalar multiplication uses a 256-bit Montgomery ladder over Jacobian
// coordinates with no early exit -- constant-time.
//
// Header-only, depends only on bn254_fp2.hpp.

#pragma once

#include "bn254_fp2.hpp"

namespace kinet::crypto::bn254 {

struct G2Affine {
    Fp2 x;
    Fp2 y;
    bool infinity;
};

struct G2Jac {
    Fp2 X;
    Fp2 Y;
    Fp2 Z;
    bool infinity;
};

inline G2Jac g2_jac_zero() noexcept {
    G2Jac r;
    r.X = fp2_zero(); r.Y = fp2_zero(); r.Z = fp2_zero();
    r.infinity = true;
    return r;
}

inline G2Jac g2_to_jac(const G2Affine& p) noexcept {
    if (p.infinity) return g2_jac_zero();
    G2Jac r;
    r.X = p.x;
    r.Y = p.y;
    r.Z = fp2_one();
    r.infinity = false;
    return r;
}

inline G2Affine g2_to_affine(const G2Jac& p) noexcept {
    G2Affine a;
    if (p.infinity || p.Z.is_zero()) {
        a.x = fp2_zero(); a.y = fp2_zero(); a.infinity = true;
        return a;
    }
    Fp2 z_inv = fp2_inv(p.Z);
    Fp2 z_inv2 = fp2_sqr(z_inv);
    Fp2 z_inv3 = fp2_mul(z_inv2, z_inv);
    a.x = fp2_mul(p.X, z_inv2);
    a.y = fp2_mul(p.Y, z_inv3);
    a.infinity = false;
    return a;
}

// dbl-2009-l from Bernstein-Lange (a=0 short Weierstrass over Fp2).
inline G2Jac g2_double(const G2Jac& p) noexcept {
    if (p.infinity) return p;
    if (p.Y.is_zero()) return g2_jac_zero();

    Fp2 A = fp2_sqr(p.X);
    Fp2 B = fp2_sqr(p.Y);
    Fp2 C = fp2_sqr(B);

    Fp2 X_plus_B = fp2_add(p.X, B);
    Fp2 D = fp2_sub(fp2_sqr(X_plus_B), A);
    D = fp2_sub(D, C);
    D = fp2_double(D);

    Fp2 E = fp2_double(A);
    E = fp2_add(E, A);
    Fp2 F = fp2_sqr(E);

    Fp2 two_D = fp2_double(D);
    Fp2 X3 = fp2_sub(F, two_D);

    Fp2 D_minus_X3 = fp2_sub(D, X3);
    Fp2 eight_C = fp2_double(C);
    eight_C = fp2_double(eight_C);
    eight_C = fp2_double(eight_C);
    Fp2 Y3 = fp2_sub(fp2_mul(E, D_minus_X3), eight_C);

    Fp2 Z3 = fp2_mul(p.Y, p.Z);
    Z3 = fp2_double(Z3);

    G2Jac r;
    r.X = X3; r.Y = Y3; r.Z = Z3;
    r.infinity = false;
    return r;
}

// add-2007-bl over Fp2.
inline G2Jac g2_add(const G2Jac& a, const G2Jac& b) noexcept {
    if (a.infinity) return b;
    if (b.infinity) return a;

    Fp2 Z1Z1 = fp2_sqr(a.Z);
    Fp2 Z2Z2 = fp2_sqr(b.Z);
    Fp2 U1 = fp2_mul(a.X, Z2Z2);
    Fp2 U2 = fp2_mul(b.X, Z1Z1);
    Fp2 S1 = fp2_mul(fp2_mul(a.Y, b.Z), Z2Z2);
    Fp2 S2 = fp2_mul(fp2_mul(b.Y, a.Z), Z1Z1);

    Fp2 H = fp2_sub(U2, U1);
    if (H.is_zero()) {
        if (S1 == S2) return g2_double(a);
        return g2_jac_zero();
    }

    Fp2 two_H = fp2_double(H);
    Fp2 I = fp2_sqr(two_H);
    Fp2 J = fp2_mul(H, I);

    Fp2 r_ = fp2_sub(S2, S1);
    r_ = fp2_double(r_);

    Fp2 V = fp2_mul(U1, I);

    Fp2 X3 = fp2_sub(fp2_sub(fp2_sqr(r_), J), fp2_double(V));
    Fp2 Y3 = fp2_sub(fp2_mul(r_, fp2_sub(V, X3)), fp2_mul(fp2_double(S1), J));
    Fp2 Z3 = fp2_sub(fp2_sub(fp2_sqr(fp2_add(a.Z, b.Z)), Z1Z1), Z2Z2);
    Z3 = fp2_mul(Z3, H);

    G2Jac out;
    out.X = X3; out.Y = Y3; out.Z = Z3;
    out.infinity = false;
    return out;
}

// Constant-time conditional move on G2Jac.
inline void g2_cmov(G2Jac& dst, const G2Jac& src, u64 cond) noexcept {
    const u64 mask = (u64)0 - (cond & 1ULL);
    auto cmov_fp2 = [mask](Fp2& d, const Fp2& s) {
        for (int i = 0; i < 4; ++i) {
            d.a0.limbs[i] ^= mask & (d.a0.limbs[i] ^ s.a0.limbs[i]);
            d.a1.limbs[i] ^= mask & (d.a1.limbs[i] ^ s.a1.limbs[i]);
        }
    };
    cmov_fp2(dst.X, src.X);
    cmov_fp2(dst.Y, src.Y);
    cmov_fp2(dst.Z, src.Z);
    const bool inf = (cond & 1ULL) ? src.infinity : dst.infinity;
    dst.infinity = inf;
}

// Constant-time scalar multiplication via Montgomery ladder over 256 bits.
inline G2Jac g2_scalar_mul(const G2Affine& p, const U256& k) noexcept {
    if (p.infinity) return g2_jac_zero();

    G2Jac R0 = g2_jac_zero();
    G2Jac R1 = g2_to_jac(p);

    for (int i = 255; i >= 0; --i) {
        const u64 bit = k.bit((unsigned)i) ? 1 : 0;

        G2Jac sum = g2_add(R0, R1);
        G2Jac dbl0 = g2_double(R0);
        G2Jac dbl1 = g2_double(R1);

        G2Jac next_R0 = dbl0;
        g2_cmov(next_R0, sum,  bit);
        G2Jac next_R1 = sum;
        g2_cmov(next_R1, dbl1, bit);

        R0 = next_R0;
        R1 = next_R1;
    }
    return R0;
}

inline bool g2_is_on_curve(const G2Affine& p) noexcept {
    if (p.infinity) return true;
    Fp2 lhs = fp2_sqr(p.y);
    Fp2 rhs = fp2_mul(fp2_sqr(p.x), p.x);
    // b' = 3 / (9 + u) (twist b coefficient)
    static const Fp2 b_twist = []() {
        Fp2 three{to_mont_fp(U256{3, 0, 0, 0}), U256{}};
        return fp2_mul_by_nonres_inv(three);
    }();
    rhs = fp2_add(rhs, b_twist);
    return lhs == rhs;
}

}  // namespace kinet::crypto::bn254

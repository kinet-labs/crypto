// First-party Jacobian-coordinate elliptic curve arithmetic for secp256k1.
//
// All field elements stored in Montgomery form throughout. Affine point
// (x, y) with x,y in Montgomery form. Jacobian point (X, Y, Z) with the
// usual relation x = X/Z^2, y = Y/Z^3.
//
// This file uses only the field functions in field.hpp and is self-contained.

#pragma once

#include "field.hpp"

namespace kinet::crypto::secp256k1 {

struct AffinePoint {
    U256 x;       // Montgomery
    U256 y;       // Montgomery
    bool infinity;
};

struct JacobianPoint {
    U256 X;       // Montgomery
    U256 Y;       // Montgomery
    U256 Z;       // Montgomery; (0,0,0) means point at infinity
    bool infinity;
};

inline JacobianPoint jac_zero() noexcept {
    JacobianPoint r;
    r.X = U256{}; r.Y = U256{}; r.Z = U256{};
    r.infinity = true;
    return r;
}

inline JacobianPoint affine_to_jacobian(const AffinePoint& p) noexcept {
    if (p.infinity) return jac_zero();
    JacobianPoint r;
    r.X = p.x;
    r.Y = p.y;
    // Z = 1 in Montgomery form is R mod p
    r.Z = R_P;
    r.infinity = false;
    return r;
}

inline AffinePoint jacobian_to_affine(const JacobianPoint& p) noexcept {
    AffinePoint a;
    if (p.infinity || p.Z.is_zero()) {
        a.x = U256{}; a.y = U256{}; a.infinity = true;
        return a;
    }
    U256 z_inv = fp_inv(p.Z);
    U256 z_inv2 = fp_sqr(z_inv);
    U256 z_inv3 = fp_mul(z_inv2, z_inv);
    a.x = fp_mul(p.X, z_inv2);
    a.y = fp_mul(p.Y, z_inv3);
    a.infinity = false;
    return a;
}

// Doubling: 2*P. Standard formulas for a=0 short Weierstrass:
//   A = X^2; B = Y^2; C = B^2;
//   D = 2 * ((X+B)^2 - A - C)
//   E = 3*A
//   F = E^2
//   X3 = F - 2*D
//   Y3 = E*(D - X3) - 8*C
//   Z3 = 2*Y*Z
inline JacobianPoint jac_double(const JacobianPoint& p) noexcept {
    if (p.infinity) return p;
    if (p.Y.is_zero()) return jac_zero();

    U256 A = fp_sqr(p.X);
    U256 B = fp_sqr(p.Y);
    U256 C = fp_sqr(B);

    U256 X_plus_B = fp_add(p.X, B);
    U256 D = fp_sub(fp_sqr(X_plus_B), A);
    D = fp_sub(D, C);
    D = fp_add(D, D);

    U256 E = fp_add(A, A);
    E = fp_add(E, A);
    U256 F = fp_sqr(E);

    U256 two_D = fp_add(D, D);
    U256 X3 = fp_sub(F, two_D);

    U256 D_minus_X3 = fp_sub(D, X3);
    U256 eight_C = fp_add(C, C);
    eight_C = fp_add(eight_C, eight_C);
    eight_C = fp_add(eight_C, eight_C);
    U256 Y3 = fp_sub(fp_mul(E, D_minus_X3), eight_C);

    U256 Z3 = fp_mul(p.Y, p.Z);
    Z3 = fp_add(Z3, Z3);

    JacobianPoint r;
    r.X = X3; r.Y = Y3; r.Z = Z3; r.infinity = false;
    return r;
}

// Mixed addition: Jacobian + Affine. Returns Jacobian.
//   U2 = X2*Z1^2; S2 = Y2*Z1^3
//   H = U2 - X1; r = S2 - Y1
//   if H == 0:
//     if r == 0: return double
//     else: return infinity
//   HH = H^2; HHH = H*HH; V = X1*HH
//   X3 = r^2 - HHH - 2*V
//   Y3 = r*(V - X3) - Y1*HHH
//   Z3 = Z1*H
inline JacobianPoint jac_add_mixed(const JacobianPoint& p, const AffinePoint& q) noexcept {
    if (p.infinity) return affine_to_jacobian(q);
    if (q.infinity) return p;

    U256 Z1Z1 = fp_sqr(p.Z);
    U256 U2 = fp_mul(q.x, Z1Z1);
    U256 S2 = fp_mul(q.y, fp_mul(Z1Z1, p.Z));

    U256 H = fp_sub(U2, p.X);
    U256 r = fp_sub(S2, p.Y);

    if (H.is_zero()) {
        if (r.is_zero()) return jac_double(p);
        return jac_zero();
    }

    U256 HH = fp_sqr(H);
    U256 HHH = fp_mul(H, HH);
    U256 V = fp_mul(p.X, HH);

    U256 r2 = fp_sqr(r);
    U256 X3 = fp_sub(r2, HHH);
    U256 two_V = fp_add(V, V);
    X3 = fp_sub(X3, two_V);

    U256 V_m_X3 = fp_sub(V, X3);
    U256 Y3 = fp_mul(r, V_m_X3);
    U256 Y1_HHH = fp_mul(p.Y, HHH);
    Y3 = fp_sub(Y3, Y1_HHH);

    U256 Z3 = fp_mul(p.Z, H);

    JacobianPoint out;
    out.X = X3; out.Y = Y3; out.Z = Z3; out.infinity = false;
    return out;
}

// Full Jacobian-Jacobian addition.
//   U1 = X1*Z2^2;     U2 = X2*Z1^2
//   S1 = Y1*Z2^3;     S2 = Y2*Z1^3
//   H = U2 - U1;      r = S2 - S1
//   X3 = r^2 - H^3 - 2*U1*H^2
//   Y3 = r*(U1*H^2 - X3) - S1*H^3
//   Z3 = Z1*Z2*H
inline JacobianPoint jac_add(const JacobianPoint& p, const JacobianPoint& q) noexcept {
    if (p.infinity) return q;
    if (q.infinity) return p;

    U256 Z1Z1 = fp_sqr(p.Z);
    U256 Z2Z2 = fp_sqr(q.Z);
    U256 U1 = fp_mul(p.X, Z2Z2);
    U256 U2 = fp_mul(q.X, Z1Z1);
    U256 S1 = fp_mul(p.Y, fp_mul(Z2Z2, q.Z));
    U256 S2 = fp_mul(q.Y, fp_mul(Z1Z1, p.Z));

    U256 H = fp_sub(U2, U1);
    U256 r = fp_sub(S2, S1);

    if (H.is_zero()) {
        if (r.is_zero()) return jac_double(p);
        return jac_zero();
    }

    U256 HH = fp_sqr(H);
    U256 HHH = fp_mul(H, HH);
    U256 U1HH = fp_mul(U1, HH);

    U256 r2 = fp_sqr(r);
    U256 X3 = fp_sub(r2, HHH);
    U256 two_U1HH = fp_add(U1HH, U1HH);
    X3 = fp_sub(X3, two_U1HH);

    U256 Y3 = fp_mul(r, fp_sub(U1HH, X3));
    U256 S1HHH = fp_mul(S1, HHH);
    Y3 = fp_sub(Y3, S1HHH);

    U256 Z3 = fp_mul(fp_mul(p.Z, q.Z), H);

    JacobianPoint out;
    out.X = X3; out.Y = Y3; out.Z = Z3; out.infinity = false;
    return out;
}

// Scalar multiplication: k * P, where k is in plain (non-Montgomery) form.
// Uses the standard left-to-right binary method. Constant-time-ish:
// always doubles, conditionally adds. Not bulletproof against side channels;
// for ecrecover that's acceptable (no secret is involved).
inline JacobianPoint jac_mul(const U256& k, const AffinePoint& p) noexcept {
    if (p.infinity) return jac_zero();
    JacobianPoint r = jac_zero();
    JacobianPoint base = affine_to_jacobian(p);
    for (int limb = 3; limb >= 0; --limb) {
        u64 w = k.limbs[limb];
        for (int bit = 63; bit >= 0; --bit) {
            r = jac_double(r);
            if ((w >> bit) & 1) r = jac_add(r, base);
        }
    }
    return r;
}

// Multi-scalar multiplication for two pairs: u1*P1 + u2*P2.
// Joint sparse form would be faster; this is the simple version.
inline JacobianPoint jac_msm2(
    const U256& u1, const AffinePoint& P1,
    const U256& u2, const AffinePoint& P2) noexcept {
    JacobianPoint a = jac_mul(u1, P1);
    JacobianPoint b = jac_mul(u2, P2);
    return jac_add(a, b);
}

}  // namespace kinet::crypto::secp256k1

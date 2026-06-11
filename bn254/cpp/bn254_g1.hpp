// First-party G1 elliptic curve arithmetic for bn254 (a=0 short Weierstrass,
// b=3). Same form as secp256k1 -- only the curve constant differs -- so the
// Jacobian doubling and addition formulas are the standard ones from Bernstein-
// Lange efl/jacobian-0/{dbl-2009-l, add-2007-bl}.
//
// All field elements are stored in Montgomery form throughout. Affine point
// (x, y) with x,y in Montgomery form. Jacobian point (X, Y, Z) with the
// usual relation x = X / Z^2, y = Y / Z^3.
//
// Constant-time scalar multiplication: Montgomery ladder over 256 bits with
// no early exit. See `g1_scalar_mul`.
//
// Self-contained -- only depends on bn254_fp.hpp.

#pragma once

#include "bn254_fp.hpp"

namespace kinet::crypto::bn254 {

struct G1Affine {
    U256 x;
    U256 y;
    bool infinity;
};

struct G1Jac {
    U256 X;
    U256 Y;
    U256 Z;
    bool infinity;
};

inline G1Jac g1_jac_zero() noexcept {
    G1Jac r;
    r.X = U256{}; r.Y = U256{}; r.Z = U256{};
    r.infinity = true;
    return r;
}

inline G1Jac g1_to_jac(const G1Affine& p) noexcept {
    if (p.infinity) return g1_jac_zero();
    G1Jac r;
    r.X = p.x;
    r.Y = p.y;
    r.Z = R_FP;
    r.infinity = false;
    return r;
}

inline G1Affine g1_to_affine(const G1Jac& p) noexcept {
    G1Affine a;
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

inline G1Jac g1_double(const G1Jac& p) noexcept {
    if (p.infinity) return p;
    if (p.Y.is_zero()) return g1_jac_zero();

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

    G1Jac r;
    r.X = X3; r.Y = Y3; r.Z = Z3;
    r.infinity = false;
    return r;
}

inline G1Jac g1_add_mixed(const G1Jac& p, const G1Affine& q) noexcept {
    if (q.infinity) return p;
    if (p.infinity) return g1_to_jac(q);

    U256 Z1Z1 = fp_sqr(p.Z);
    U256 U2   = fp_mul(q.x, Z1Z1);
    U256 S2   = fp_mul(fp_mul(q.y, p.Z), Z1Z1);

    U256 H = fp_sub(U2, p.X);
    if (H.is_zero()) {
        if (S2 == p.Y) return g1_double(p);
        return g1_jac_zero();
    }

    U256 HH = fp_sqr(H);
    U256 I  = fp_add(HH, HH);
    I = fp_add(I, I);
    U256 J  = fp_mul(H, I);

    U256 r_ = fp_sub(S2, p.Y);
    r_ = fp_add(r_, r_);

    U256 V = fp_mul(p.X, I);

    U256 X3 = fp_sub(fp_sub(fp_sqr(r_), J), fp_add(V, V));
    U256 Y3 = fp_sub(fp_mul(r_, fp_sub(V, X3)), fp_mul(fp_add(p.Y, p.Y), J));
    U256 Z3 = fp_sub(fp_sub(fp_sqr(fp_add(p.Z, H)), Z1Z1), HH);

    G1Jac out;
    out.X = X3; out.Y = Y3; out.Z = Z3;
    out.infinity = false;
    return out;
}

inline G1Jac g1_add(const G1Jac& a, const G1Jac& b) noexcept {
    if (a.infinity) return b;
    if (b.infinity) return a;

    U256 Z1Z1 = fp_sqr(a.Z);
    U256 Z2Z2 = fp_sqr(b.Z);
    U256 U1 = fp_mul(a.X, Z2Z2);
    U256 U2 = fp_mul(b.X, Z1Z1);
    U256 S1 = fp_mul(fp_mul(a.Y, b.Z), Z2Z2);
    U256 S2 = fp_mul(fp_mul(b.Y, a.Z), Z1Z1);

    U256 H = fp_sub(U2, U1);
    if (H.is_zero()) {
        if (S1 == S2) return g1_double(a);
        return g1_jac_zero();
    }

    U256 two_H = fp_add(H, H);
    U256 I = fp_sqr(two_H);
    U256 J = fp_mul(H, I);

    U256 r_ = fp_sub(S2, S1);
    r_ = fp_add(r_, r_);

    U256 V = fp_mul(U1, I);

    U256 X3 = fp_sub(fp_sub(fp_sqr(r_), J), fp_add(V, V));
    U256 Y3 = fp_sub(fp_mul(r_, fp_sub(V, X3)), fp_mul(fp_add(S1, S1), J));
    U256 Z3 = fp_sub(fp_sub(fp_sqr(fp_add(a.Z, b.Z)), Z1Z1), Z2Z2);
    Z3 = fp_mul(Z3, H);

    G1Jac out;
    out.X = X3; out.Y = Y3; out.Z = Z3;
    out.infinity = false;
    return out;
}

inline void cmov(G1Jac& dst, const G1Jac& src, u64 cond) noexcept {
    const u64 mask = (u64)0 - (cond & 1ULL);
    for (int i = 0; i < 4; ++i) {
        dst.X.limbs[i] ^= mask & (dst.X.limbs[i] ^ src.X.limbs[i]);
        dst.Y.limbs[i] ^= mask & (dst.Y.limbs[i] ^ src.Y.limbs[i]);
        dst.Z.limbs[i] ^= mask & (dst.Z.limbs[i] ^ src.Z.limbs[i]);
    }
    const bool inf = (cond & 1ULL) ? src.infinity : dst.infinity;
    dst.infinity = inf;
}

// Constant-time scalar multiplication using a Montgomery ladder over 256 bits.
inline G1Jac g1_scalar_mul(const G1Affine& p, const U256& k) noexcept {
    if (p.infinity) return g1_jac_zero();

    G1Jac R0 = g1_jac_zero();
    G1Jac R1 = g1_to_jac(p);

    for (int i = 255; i >= 0; --i) {
        const u64 bit = k.bit((unsigned)i) ? 1 : 0;

        G1Jac sum = g1_add(R0, R1);
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
    U256 lhs = fp_sqr(p.y);
    U256 rhs = fp_mul(fp_sqr(p.x), p.x);
    rhs = fp_add(rhs, fp_three());
    return lhs == rhs;
}

}  // namespace kinet::crypto::bn254

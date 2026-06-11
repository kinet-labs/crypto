// First-party Fp2 = Fp[u] / (u^2 + 1) for bn254.
//
// Element layout: { a0, a1 } meaning a0 + a1 * u, both in Montgomery Fp form.
//
// Algorithm references (transliterated, no upstream code):
//   * Multiplication / Squaring / Inverse from Algorithms 8 / 22 in
//     "High-Speed Software Implementation of the Optimal Ate Pairing over
//     Barreto-Naehrig Curves", Aranha-Karabina-Longa-Gebotys-Lopez 2010,
//     https://eprint.iacr.org/2010/354.pdf
//   * Multiplication by non-residue (9, 1) is the identity
//        (a0, a1) -> (9*a0 - a1, a0 + 9*a1)
//
// Header-only because the rest of the bn254 first-party tower is header-only;
// it keeps inlining behaviour consistent with bn254_fp.hpp / bn254_g1.hpp.

#pragma once

#include "bn254_fp.hpp"

namespace kinet::crypto::bn254 {

struct Fp2 {
    U256 a0;
    U256 a1;

    constexpr Fp2() = default;
    constexpr Fp2(const U256& x, const U256& y) : a0(x), a1(y) {}

    bool is_zero() const noexcept { return a0.is_zero() && a1.is_zero(); }

    bool operator==(const Fp2& o) const noexcept {
        return a0 == o.a0 && a1 == o.a1;
    }
    bool operator!=(const Fp2& o) const noexcept { return !(*this == o); }
};

inline Fp2 fp2_zero() noexcept { return Fp2{U256{}, U256{}}; }

inline Fp2 fp2_one() noexcept {
    return Fp2{to_mont_fp(U256{1, 0, 0, 0}), U256{}};
}

inline Fp2 fp2_add(const Fp2& x, const Fp2& y) noexcept {
    return Fp2{fp_add(x.a0, y.a0), fp_add(x.a1, y.a1)};
}

inline Fp2 fp2_sub(const Fp2& x, const Fp2& y) noexcept {
    return Fp2{fp_sub(x.a0, y.a0), fp_sub(x.a1, y.a1)};
}

inline Fp2 fp2_neg(const Fp2& x) noexcept {
    return Fp2{fp_neg(x.a0), fp_neg(x.a1)};
}

inline Fp2 fp2_double(const Fp2& x) noexcept {
    return Fp2{fp_add(x.a0, x.a0), fp_add(x.a1, x.a1)};
}

inline Fp2 fp2_conjugate(const Fp2& x) noexcept {
    return Fp2{x.a0, fp_neg(x.a1)};
}

inline Fp2 fp2_mul_by_fp(const Fp2& x, const U256& y) noexcept {
    return Fp2{fp_mul(x.a0, y), fp_mul(x.a1, y)};
}

// (x.a0 + x.a1 * u) * (y.a0 + y.a1 * u)
//   = (x.a0*y.a0 - x.a1*y.a1) + (x.a0*y.a1 + x.a1*y.a0) * u  since u^2 = -1
// Karatsuba: a = (x.a0+x.a1)*(y.a0+y.a1); b = x.a0*y.a0; c = x.a1*y.a1
//   a1 = a - b - c;   a0 = b - c
inline Fp2 fp2_mul(const Fp2& x, const Fp2& y) noexcept {
    U256 a = fp_mul(fp_add(x.a0, x.a1), fp_add(y.a0, y.a1));
    U256 b = fp_mul(x.a0, y.a0);
    U256 c = fp_mul(x.a1, y.a1);
    Fp2 r;
    r.a1 = fp_sub(fp_sub(a, b), c);
    r.a0 = fp_sub(b, c);
    return r;
}

// (x.a0 + x.a1*u)^2 = (x.a0+x.a1)*(x.a0-x.a1) + 2*x.a0*x.a1 * u
//   since (a+bu)^2 = a^2 - b^2 + 2ab u
inline Fp2 fp2_sqr(const Fp2& x) noexcept {
    U256 a = fp_mul(fp_add(x.a0, x.a1), fp_sub(x.a0, x.a1));
    U256 b = fp_mul(x.a0, x.a1);
    Fp2 r;
    r.a0 = a;
    r.a1 = fp_add(b, b);
    return r;
}

// (a0 + a1*u)^-1 = (a0 - a1*u) / (a0^2 + a1^2)
inline Fp2 fp2_inv(const Fp2& x) noexcept {
    U256 t0 = fp_sqr(x.a0);
    U256 t1 = fp_sqr(x.a1);
    U256 t  = fp_add(t0, t1);
    U256 ti = fp_inv(t);
    Fp2 r;
    r.a0 = fp_mul(x.a0, ti);
    r.a1 = fp_neg(fp_mul(x.a1, ti));
    return r;
}

// MulByNonResidue multiplies an Fp2 element by the cubic non-residue (9, 1).
// (a0 + a1 u) * (9 + u) = (9 a0 - a1) + (a0 + 9 a1) u
inline Fp2 fp2_mul_by_nonres(const Fp2& x) noexcept {
    // 9*a0 = 8*a0 + a0  (three doublings + add)
    U256 t0 = fp_add(x.a0, x.a0);   // 2 a0
    t0 = fp_add(t0, t0);            // 4 a0
    t0 = fp_add(t0, t0);            // 8 a0
    U256 t1 = fp_add(x.a1, x.a1);   // 2 a1
    t1 = fp_add(t1, t1);            // 4 a1
    t1 = fp_add(t1, t1);            // 8 a1
    Fp2 r;
    r.a0 = fp_sub(fp_add(t0, x.a0), x.a1);   // 9 a0 - a1
    r.a1 = fp_add(fp_add(t1, x.a1), x.a0);   // 9 a1 + a0
    return r;
}

// (9+u)^-1 = (9 - u) / (81 + 1) = (9 - u) / 82.
// gnark-crypto stores the constant directly. We compute it once via fp_inv
// at first use; since we only need it for the b-twist coefficient at curve
// init, it lives behind a getter.
inline Fp2 fp2_mul_by_nonres_inv(const Fp2& x) noexcept {
    // Use Inverse-times-x pattern: divisor = (9 + u). Compute once.
    static const Fp2 inv_nr = []() {
        Fp2 nr{to_mont_fp(U256{9, 0, 0, 0}), to_mont_fp(U256{1, 0, 0, 0})};
        return fp2_inv(nr);
    }();
    return fp2_mul(x, inv_nr);
}

}  // namespace kinet::crypto::bn254

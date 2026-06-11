// First-party Fp6 = Fp2[v] / (v^3 - (9 + u)) for bn254.
//
// Element layout: { b0, b1, b2 } meaning b0 + b1 v + b2 v^2.
//
// Multiplication / squaring / inverse follow Algorithms 13, 16, 17 from
// Aranha-Karabina-Longa-Gebotys-Lopez 2010 (eprint 2010/354). MulByNonResidue
// implements the cyclic shift v * (b0 + b1 v + b2 v^2) =
//   (9+u) b2 + b0 v + b1 v^2.
//
// Header-only, depends only on bn254_fp2.hpp.

#pragma once

#include "bn254_fp2.hpp"

namespace kinet::crypto::bn254 {

struct Fp6 {
    Fp2 b0;
    Fp2 b1;
    Fp2 b2;

    constexpr Fp6() = default;
    constexpr Fp6(const Fp2& x, const Fp2& y, const Fp2& z) : b0(x), b1(y), b2(z) {}

    bool is_zero() const noexcept {
        return b0.is_zero() && b1.is_zero() && b2.is_zero();
    }

    bool operator==(const Fp6& o) const noexcept {
        return b0 == o.b0 && b1 == o.b1 && b2 == o.b2;
    }
    bool operator!=(const Fp6& o) const noexcept { return !(*this == o); }
};

inline Fp6 fp6_zero() noexcept { return Fp6{fp2_zero(), fp2_zero(), fp2_zero()}; }
inline Fp6 fp6_one() noexcept { return Fp6{fp2_one(), fp2_zero(), fp2_zero()}; }

inline Fp6 fp6_add(const Fp6& x, const Fp6& y) noexcept {
    return Fp6{fp2_add(x.b0, y.b0), fp2_add(x.b1, y.b1), fp2_add(x.b2, y.b2)};
}

inline Fp6 fp6_sub(const Fp6& x, const Fp6& y) noexcept {
    return Fp6{fp2_sub(x.b0, y.b0), fp2_sub(x.b1, y.b1), fp2_sub(x.b2, y.b2)};
}

inline Fp6 fp6_neg(const Fp6& x) noexcept {
    return Fp6{fp2_neg(x.b0), fp2_neg(x.b1), fp2_neg(x.b2)};
}

inline Fp6 fp6_double(const Fp6& x) noexcept {
    return Fp6{fp2_double(x.b0), fp2_double(x.b1), fp2_double(x.b2)};
}

// Multiplication by v: (b0 + b1 v + b2 v^2) * v = (9+u) b2 + b0 v + b1 v^2.
inline Fp6 fp6_mul_by_nonres(const Fp6& x) noexcept {
    return Fp6{fp2_mul_by_nonres(x.b2), x.b0, x.b1};
}

// Algorithm 13 from eprint 2010/354.
inline Fp6 fp6_mul(const Fp6& x, const Fp6& y) noexcept {
    Fp2 t0 = fp2_mul(x.b0, y.b0);
    Fp2 t1 = fp2_mul(x.b1, y.b1);
    Fp2 t2 = fp2_mul(x.b2, y.b2);

    Fp2 c0 = fp2_add(x.b1, x.b2);
    Fp2 tmp = fp2_add(y.b1, y.b2);
    c0 = fp2_mul(c0, tmp);
    c0 = fp2_sub(c0, t1);
    c0 = fp2_sub(c0, t2);
    c0 = fp2_mul_by_nonres(c0);
    c0 = fp2_add(c0, t0);

    Fp2 c1 = fp2_add(x.b0, x.b1);
    tmp = fp2_add(y.b0, y.b1);
    c1 = fp2_mul(c1, tmp);
    c1 = fp2_sub(c1, t0);
    c1 = fp2_sub(c1, t1);
    Fp2 t2_nr = fp2_mul_by_nonres(t2);
    c1 = fp2_add(c1, t2_nr);

    Fp2 c2 = fp2_add(x.b0, x.b2);
    tmp = fp2_add(y.b0, y.b2);
    c2 = fp2_mul(c2, tmp);
    c2 = fp2_sub(c2, t0);
    c2 = fp2_sub(c2, t2);
    c2 = fp2_add(c2, t1);

    return Fp6{c0, c1, c2};
}

// Algorithm 16 from eprint 2010/354.
inline Fp6 fp6_sqr(const Fp6& x) noexcept {
    Fp2 c4 = fp2_mul(x.b0, x.b1);
    c4 = fp2_double(c4);
    Fp2 c5 = fp2_sqr(x.b2);
    Fp2 c1 = fp2_mul_by_nonres(c5);
    c1 = fp2_add(c1, c4);
    Fp2 c2 = fp2_sub(c4, c5);
    Fp2 c3 = fp2_sqr(x.b0);
    Fp2 c4b = fp2_sub(x.b0, x.b1);
    c4b = fp2_add(c4b, x.b2);
    Fp2 c5b = fp2_mul(x.b1, x.b2);
    c5b = fp2_double(c5b);
    c4b = fp2_sqr(c4b);
    Fp2 c0 = fp2_mul_by_nonres(c5b);
    c0 = fp2_add(c0, c3);

    Fp2 z2 = fp2_add(c2, c4b);
    z2 = fp2_add(z2, c5b);
    z2 = fp2_sub(z2, c3);

    return Fp6{c0, c1, z2};
}

// Algorithm 17 from eprint 2010/354 (with corrected step 9 t1 - t4).
inline Fp6 fp6_inv(const Fp6& x) noexcept {
    Fp2 t0 = fp2_sqr(x.b0);
    Fp2 t1 = fp2_sqr(x.b1);
    Fp2 t2 = fp2_sqr(x.b2);
    Fp2 t3 = fp2_mul(x.b0, x.b1);
    Fp2 t4 = fp2_mul(x.b0, x.b2);
    Fp2 t5 = fp2_mul(x.b1, x.b2);

    Fp2 c0 = fp2_mul_by_nonres(t5);
    c0 = fp2_neg(c0);
    c0 = fp2_add(c0, t0);

    Fp2 c1 = fp2_mul_by_nonres(t2);
    c1 = fp2_sub(c1, t3);

    Fp2 c2 = fp2_sub(t1, t4);

    Fp2 t6 = fp2_mul(x.b0, c0);
    Fp2 d1 = fp2_mul(x.b2, c1);
    Fp2 d2 = fp2_mul(x.b1, c2);
    Fp2 d  = fp2_add(d1, d2);
    d = fp2_mul_by_nonres(d);
    t6 = fp2_add(t6, d);
    Fp2 t6_inv = fp2_inv(t6);

    return Fp6{fp2_mul(c0, t6_inv), fp2_mul(c1, t6_inv), fp2_mul(c2, t6_inv)};
}

// Multiplication by a sparse element (c0, c1, 0).
// Used by the Miller loop to fold each line evaluation into the running Fp12.
inline Fp6 fp6_mul_by_01(const Fp6& z, const Fp2& c0, const Fp2& c1) noexcept {
    Fp2 a = fp2_mul(z.b0, c0);
    Fp2 b = fp2_mul(z.b1, c1);

    Fp2 tmp = fp2_add(z.b1, z.b2);
    Fp2 t0 = fp2_mul(c1, tmp);
    t0 = fp2_sub(t0, b);
    t0 = fp2_mul_by_nonres(t0);
    t0 = fp2_add(t0, a);

    tmp = fp2_add(z.b0, z.b2);
    Fp2 t2 = fp2_mul(c0, tmp);
    t2 = fp2_sub(t2, a);
    t2 = fp2_add(t2, b);

    Fp2 t1 = fp2_add(c0, c1);
    tmp = fp2_add(z.b0, z.b1);
    t1 = fp2_mul(t1, tmp);
    t1 = fp2_sub(t1, a);
    t1 = fp2_sub(t1, b);

    return Fp6{t0, t1, t2};
}

// Multiplication of an Fp6 by an Fp2.
inline Fp6 fp6_mul_by_fp2(const Fp6& z, const Fp2& y) noexcept {
    return Fp6{fp2_mul(z.b0, y), fp2_mul(z.b1, y), fp2_mul(z.b2, y)};
}

}  // namespace kinet::crypto::bn254

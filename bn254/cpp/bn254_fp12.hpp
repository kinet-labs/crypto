// First-party Fp12 = Fp6[w] / (w^2 - v) for bn254. The result is the GT
// target field of the optimal-ate pairing.
//
// Element layout: { c0, c1 } meaning c0 + c1 w. Implementation closely
// follows Aranha-Karabina-Longa-Gebotys-Lopez 2010 (eprint 2010/354)
// algorithms 22 (square), generic Karatsuba mul, and 23 (inverse).
//
// Header-only, depends only on bn254_fp6.hpp.

#pragma once

#include "bn254_fp6.hpp"

namespace kinet::crypto::bn254 {

struct Fp12 {
    Fp6 c0;
    Fp6 c1;

    constexpr Fp12() = default;
    constexpr Fp12(const Fp6& x, const Fp6& y) : c0(x), c1(y) {}

    bool is_zero() const noexcept { return c0.is_zero() && c1.is_zero(); }

    bool operator==(const Fp12& o) const noexcept {
        return c0 == o.c0 && c1 == o.c1;
    }
    bool operator!=(const Fp12& o) const noexcept { return !(*this == o); }
};

inline Fp12 fp12_zero() noexcept { return Fp12{fp6_zero(), fp6_zero()}; }
inline Fp12 fp12_one() noexcept { return Fp12{fp6_one(), fp6_zero()}; }

inline bool fp12_is_one(const Fp12& z) noexcept {
    return z.c1.is_zero() && z.c0.b1.is_zero() && z.c0.b2.is_zero()
        && z.c0.b0.a1.is_zero()
        && z.c0.b0.a0 == fp12_one().c0.b0.a0;
}

inline Fp12 fp12_add(const Fp12& x, const Fp12& y) noexcept {
    return Fp12{fp6_add(x.c0, y.c0), fp6_add(x.c1, y.c1)};
}
inline Fp12 fp12_sub(const Fp12& x, const Fp12& y) noexcept {
    return Fp12{fp6_sub(x.c0, y.c0), fp6_sub(x.c1, y.c1)};
}
inline Fp12 fp12_neg(const Fp12& x) noexcept {
    return Fp12{fp6_neg(x.c0), fp6_neg(x.c1)};
}

// (c0 + c1 w) * (d0 + d1 w) = (c0 d0 + v c1 d1) + ((c0+c1)(d0+d1) - c0 d0 - c1 d1) w
inline Fp12 fp12_mul(const Fp12& x, const Fp12& y) noexcept {
    Fp6 a = fp6_add(x.c0, x.c1);
    Fp6 b = fp6_add(y.c0, y.c1);
    a = fp6_mul(a, b);
    b = fp6_mul(x.c0, y.c0);
    Fp6 c = fp6_mul(x.c1, y.c1);
    Fp6 r1 = fp6_sub(fp6_sub(a, b), c);
    Fp6 r0 = fp6_add(fp6_mul_by_nonres(c), b);
    return Fp12{r0, r1};
}

// Algorithm 22 from eprint 2010/354 (Chung-Hasan).
inline Fp12 fp12_sqr(const Fp12& x) noexcept {
    Fp6 c0 = fp6_sub(x.c0, x.c1);
    Fp6 c3 = fp6_mul_by_nonres(x.c1);
    c3 = fp6_neg(c3);
    c3 = fp6_add(x.c0, c3);
    Fp6 c2 = fp6_mul(x.c0, x.c1);
    c0 = fp6_mul(c0, c3);
    c0 = fp6_add(c0, c2);
    Fp6 r1 = fp6_double(c2);
    c2 = fp6_mul_by_nonres(c2);
    Fp6 r0 = fp6_add(c0, c2);
    return Fp12{r0, r1};
}

// Algorithm 23 from eprint 2010/354.
inline Fp12 fp12_inv(const Fp12& x) noexcept {
    Fp6 t0 = fp6_sqr(x.c0);
    Fp6 t1 = fp6_sqr(x.c1);
    Fp6 tmp = fp6_mul_by_nonres(t1);
    t0 = fp6_sub(t0, tmp);
    Fp6 t0_inv = fp6_inv(t0);
    Fp6 r0 = fp6_mul(x.c0, t0_inv);
    Fp6 r1 = fp6_neg(fp6_mul(x.c1, t0_inv));
    return Fp12{r0, r1};
}

// Conjugation in Fp12 over Fp6: (c0 + c1 w) -> (c0 - c1 w).
inline Fp12 fp12_conjugate(const Fp12& x) noexcept {
    return Fp12{x.c0, fp6_neg(x.c1)};
}

// Sparse multiplication by an element of the form
//   (c0, 0, 0, c3, c4, 0)  i.e. C0 = (c0,0,0), C1 = (c3,c4,0).
// Used to fold each Miller-loop line evaluation into the running Fp12.
//
// Layout reminder (gnark uses subscript order C0=B0,B1,B2 then C1=B0,B1,B2,
// so coefficients are (c0,c1,c2,c3,c4,c5)). Here we pass the only three
// non-zero ones (c0,c3,c4).
inline Fp12 fp12_mul_by_034(const Fp12& z, const Fp2& c0, const Fp2& c3, const Fp2& c4) noexcept {
    Fp6 a = fp6_mul_by_fp2(z.c0, c0);
    Fp6 b = z.c1;
    b = fp6_mul_by_01(b, c3, c4);

    Fp2 d0 = fp2_add(c0, c3);
    Fp6 d = fp6_add(z.c0, z.c1);
    d = fp6_mul_by_01(d, d0, c4);

    Fp6 r1 = fp6_add(a, b);
    r1 = fp6_neg(r1);
    r1 = fp6_add(r1, d);
    Fp6 r0 = fp6_mul_by_nonres(b);
    r0 = fp6_add(r0, a);
    return Fp12{r0, r1};
}

// Mul of two sparse (c0,0,0,c3,c4,0) elements -> dense (5 Fp2 coords; c5=0).
// Returns the array { z00, x3, x34, x03, x04 }, gnark layout.
struct Fp12Sparse5 {
    Fp2 v00;  // C0.B0
    Fp2 v01;  // C0.B1
    Fp2 v02;  // C0.B2
    Fp2 v10;  // C1.B0
    Fp2 v11;  // C1.B1
};

inline Fp12Sparse5 fp12_mul_034_by_034(
    const Fp2& d0, const Fp2& d3, const Fp2& d4,
    const Fp2& c0, const Fp2& c3, const Fp2& c4) noexcept {
    Fp2 x0 = fp2_mul(c0, d0);
    Fp2 x3 = fp2_mul(c3, d3);
    Fp2 x4 = fp2_mul(c4, d4);

    Fp2 tmp = fp2_add(c0, c4);
    Fp2 x04 = fp2_add(d0, d4);
    x04 = fp2_mul(x04, tmp);
    x04 = fp2_sub(x04, x0);
    x04 = fp2_sub(x04, x4);

    tmp = fp2_add(c0, c3);
    Fp2 x03 = fp2_add(d0, d3);
    x03 = fp2_mul(x03, tmp);
    x03 = fp2_sub(x03, x0);
    x03 = fp2_sub(x03, x3);

    tmp = fp2_add(c3, c4);
    Fp2 x34 = fp2_add(d3, d4);
    x34 = fp2_mul(x34, tmp);
    x34 = fp2_sub(x34, x3);
    x34 = fp2_sub(x34, x4);

    Fp2 z00 = fp2_mul_by_nonres(x4);
    z00 = fp2_add(z00, x0);
    return Fp12Sparse5{z00, x3, x34, x03, x04};
}

// Multiplication by a (c0, c1, c2, c3, c4, 0)-shaped element. This is the
// product of two sparse 034-shaped elements, so it has five non-zero Fp2
// coefficients.
inline Fp12 fp12_mul_by_01234(const Fp12& z, const Fp12Sparse5& x) noexcept {
    Fp6 c0_part{x.v00, x.v01, x.v02};
    Fp6 c1_part{x.v10, x.v11, fp2_zero()};

    Fp6 a = fp6_add(z.c0, z.c1);
    Fp6 b = fp6_add(c0_part, c1_part);
    a = fp6_mul(a, b);

    b = fp6_mul(z.c0, c0_part);
    Fp6 c = fp6_mul_by_01(z.c1, x.v10, x.v11);

    Fp6 r1 = fp6_sub(a, b);
    r1 = fp6_sub(r1, c);

    Fp6 r0 = fp6_mul_by_nonres(c);
    r0 = fp6_add(r0, b);

    return Fp12{r0, r1};
}

// Modular exponentiation by an unsigned 320-bit limb sequence.
// Used only when no precomputed addition chain applies.
template <int LIMBS>
inline Fp12 fp12_pow(const Fp12& x, const u64 (&e)[LIMBS]) noexcept {
    Fp12 result = fp12_one();
    Fp12 base = x;
    for (int limb = 0; limb < LIMBS; ++limb) {
        u64 w = e[limb];
        for (int bit = 0; bit < 64; ++bit) {
            if ((w >> bit) & 1) result = fp12_mul(result, base);
            base = fp12_sqr(base);
        }
    }
    return result;
}

}  // namespace kinet::crypto::bn254

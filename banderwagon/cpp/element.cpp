// SPDX-License-Identifier: Apache-2.0
//
// banderwagon/element.cpp -- Banderwagon group element ops.
// Algorithm references match kinet-labs/crypto/ipa/banderwagon and gnark-crypto
// bls12-381/bandersnatch:
//   - Projective add  : http://eprint.iacr.org/2008/013.pdf  (Sec. 6, "add-2008-bbjlp")
//   - Projective dbl  : (same paper, "dbl-2008-bbjlp")
//   - Banderwagon eq  : x1*y2 == y1*x2  (the 2-torsion quotient).
//   - Compressed serde: see element.hpp prologue.
// First-party. No vendoring.

#include "element.hpp"

#include <cstdint>
#include <cstring>

namespace kinet::banderwagon {

namespace {

// ----- Curve constants in Montgomery form ----------------------------------

// a = -5 mod q, in Montgomery form. Compute lazily once.
Fp compute_a() {
    // Five = 5 in Montgomery form: from canonical bytes.
    std::uint8_t five_le[32] = {0};
    five_le[0] = 5;
    Fp five;
    Fp::from_bytes_le(five_le, five);
    return Fp::neg(five);
}

// d = 45022363124591815672509500913686876175488063829319466900776701791074614335719
//   = 0x6389c12633c267cbc66e3bf86be3b6d8cb66677177e54f92b369f2f5188d58e7
// LE bytes (computed once via Python; documented at top of file).
Fp compute_d() {
    constexpr std::uint8_t d_le[32] = {
        0xe7, 0x58, 0x8d, 0x18, 0xf5, 0xf2, 0x69, 0xb3,
        0x92, 0x4f, 0xe5, 0x77, 0x71, 0x67, 0x66, 0xcb,
        0xd8, 0xb6, 0xe3, 0x6b, 0xf8, 0x3b, 0x6e, 0xc6,
        0xcb, 0x67, 0xc2, 0x33, 0x26, 0xc1, 0x89, 0x63
    };
    Fp d;
    Fp::from_bytes_le(d_le, d);
    return d;
}

// Generator (Bandersnatch base, also a generator of the prime-order subgroup
// when treated under the Banderwagon equivalence). Coordinates from gnark.
Fp gen_x() {
    constexpr std::uint8_t bx_le[32] = {
        0x18, 0xae, 0x52, 0xa2, 0x66, 0x18, 0xe7, 0xe1,
        0x65, 0x84, 0x99, 0xad, 0x22, 0xc0, 0x79, 0x2b,
        0xf3, 0x42, 0xbe, 0x7b, 0x77, 0x11, 0x37, 0x74,
        0xc5, 0x34, 0x0b, 0x2c, 0xcc, 0x32, 0xc1, 0x29
    };
    Fp x;
    Fp::from_bytes_le(bx_le, x);
    return x;
}

Fp gen_y() {
    constexpr std::uint8_t by_le[32] = {
        0x66, 0x41, 0x97, 0xcc, 0xb6, 0x67, 0x31, 0x5e,
        0x60, 0x64, 0xe4, 0xee, 0x81, 0xad, 0x8c, 0x35,
        0x86, 0xd5, 0xdc, 0xba, 0x50, 0x8b, 0x7d, 0x15,
        0x0f, 0x3e, 0x12, 0xda, 0x9e, 0x66, 0x6c, 0x2a
    };
    Fp y;
    Fp::from_bytes_le(by_le, y);
    return y;
}

// Lazy initialisation guarded by static-local. Cheap; no contention concerns.
const Fp& curve_a_impl() {
    static const Fp v = compute_a();
    return v;
}

const Fp& curve_d_impl() {
    static const Fp v = compute_d();
    return v;
}

const Fp& gen_x_impl() {
    static const Fp v = gen_x();
    return v;
}

const Fp& gen_y_impl() {
    static const Fp v = gen_y();
    return v;
}

// (q+1)/4 — exponent for the y-from-x reconstruction is not used; we use
// Fp::sqrt directly.

}  // namespace

const Fp& curve_a() { return curve_a_impl(); }
const Fp& curve_d() { return curve_d_impl(); }

// ----- Constants -----------------------------------------------------------

Element Element::identity() {
    Element e;
    e.X = Fp::zero();
    e.Y = Fp::one();
    e.Z = Fp::one();
    return e;
}

Element Element::generator() {
    Element e;
    e.X = gen_x_impl();
    e.Y = gen_y_impl();
    e.Z = Fp::one();
    return e;
}

// ----- Predicates ----------------------------------------------------------

bool Element::is_identity() const {
    // (0 : * : *) with x = 0 and y = z corresponds to identity.
    return X.is_zero() && Y.equal(Z);
}

bool Element::is_on_curve() const {
    // Convert to affine to evaluate  a*x^2 + y^2 == 1 + d*x^2*y^2.
    if (Z.is_zero()) return false;
    Fp zinv = Fp::inv(Z);
    Fp x = Fp::mul(X, zinv);
    Fp y = Fp::mul(Y, zinv);
    Fp x2 = Fp::square(x);
    Fp y2 = Fp::square(y);
    Fp lhs = Fp::add(Fp::mul(curve_a_impl(), x2), y2);
    Fp x2y2 = Fp::mul(x2, y2);
    Fp rhs = Fp::add(Fp::one(), Fp::mul(curve_d_impl(), x2y2));
    return lhs.equal(rhs);
}

// Banderwagon equality: identifies (x,y) with (-x,-y).
// Uses projective form: x1*y2 == y1*x2.
// Reject the spurious (0,0) "two-torsion" point (not in the group).
bool Element::equal(const Element& p1, const Element& p2) {
    // (0:0:Z) is invalid in Banderwagon.
    if (p1.X.is_zero() && p1.Y.is_zero()) return false;
    if (p2.X.is_zero() && p2.Y.is_zero()) return false;
    Fp lhs = Fp::mul(p1.X, p2.Y);
    Fp rhs = Fp::mul(p1.Y, p2.X);
    return lhs.equal(rhs);
}

// ----- Group ops -----------------------------------------------------------

Element Element::neg(const Element& p) {
    Element r;
    r.X = Fp::neg(p.X);
    r.Y = p.Y;
    r.Z = p.Z;
    return r;
}

// Unified projective addition (twisted Edwards, "add-2008-bbjlp"):
//   A = Z1*Z2,  B = A^2
//   C = X1*X2,  D = Y1*Y2
//   E = d*C*D,  F = B - E,  G = B + E
//   H = X1+Y1,  I = X2+Y2
//   X3 = ((H*I) - C - D) * A * F
//   Y3 = (D - a*C) * A * G
//   Z3 = F * G
Element Element::add(const Element& p1, const Element& p2) {
    const Fp& a_const = curve_a_impl();
    const Fp& d_const = curve_d_impl();

    Fp A = Fp::mul(p1.Z, p2.Z);
    Fp B = Fp::square(A);
    Fp C = Fp::mul(p1.X, p2.X);
    Fp D = Fp::mul(p1.Y, p2.Y);
    Fp E = Fp::mul(d_const, Fp::mul(C, D));
    Fp F = Fp::sub(B, E);
    Fp G = Fp::add(B, E);
    Fp H = Fp::add(p1.X, p1.Y);
    Fp I = Fp::add(p2.X, p2.Y);

    Element r;
    // X3 = ((H*I) - C - D) * A * F
    Fp t1 = Fp::mul(H, I);
    t1 = Fp::sub(t1, C);
    t1 = Fp::sub(t1, D);
    t1 = Fp::mul(t1, A);
    r.X = Fp::mul(t1, F);

    // Y3 = (D - a*C) * A * G
    Fp aC = Fp::mul(a_const, C);
    Fp t2 = Fp::sub(D, aC);
    t2 = Fp::mul(t2, A);
    r.Y = Fp::mul(t2, G);

    // Z3 = F * G
    r.Z = Fp::mul(F, G);
    return r;
}

// Dedicated doubling ("dbl-2008-bbjlp"):
//   B = (X+Y)^2
//   C = X^2,  D = Y^2
//   E = a*C
//   F = E + D
//   H = Z^2
//   J = F - 2*H
//   X3 = (B - C - D) * J
//   Y3 = F * (E - D)
//   Z3 = F * J
Element Element::double_self(const Element& p) {
    const Fp& a_const = curve_a_impl();

    Fp XY = Fp::add(p.X, p.Y);
    Fp B = Fp::square(XY);
    Fp C = Fp::square(p.X);
    Fp D = Fp::square(p.Y);
    Fp E = Fp::mul(a_const, C);
    Fp F = Fp::add(E, D);
    Fp H = Fp::square(p.Z);
    Fp twoH = Fp::add(H, H);
    Fp J = Fp::sub(F, twoH);

    Element r;
    Fp t1 = Fp::sub(B, C);
    t1 = Fp::sub(t1, D);
    r.X = Fp::mul(t1, J);
    r.Y = Fp::mul(F, Fp::sub(E, D));
    r.Z = Fp::mul(F, J);
    return r;
}

Element Element::sub(const Element& p1, const Element& p2) {
    return Element::add(p1, Element::neg(p2));
}

// Constant-time scalar multiplication.
//
// Right-to-left double-and-add over the canonical Fr scalar bytes (32 bytes
// LE). At each step we compute both `acc + base` and `acc` and select via
// constant-time mask. The base is doubled regardless.
//
// This is constant-time wrt the *value* of the scalar (operation count is
// fixed, branch is masked, no early exit). It is not constant-time across
// different *points* (Fp ops are constant-time, but cache footprint is
// implementation-defined).
namespace {

// Constant-time conditional move: dst = mask ? src : dst. mask is 0 or all-1.
inline void cmov(Element& dst, const Element& src, std::uint64_t mask) {
    for (int i = 0; i < 4; ++i) {
        dst.X.limbs[i] = (dst.X.limbs[i] & ~mask) | (src.X.limbs[i] & mask);
        dst.Y.limbs[i] = (dst.Y.limbs[i] & ~mask) | (src.Y.limbs[i] & mask);
        dst.Z.limbs[i] = (dst.Z.limbs[i] & ~mask) | (src.Z.limbs[i] & mask);
    }
}

}  // namespace

Element Element::scalar_mul(const Element& p, const Fr& s) {
    // Convert Fr from Montgomery to canonical 32-byte LE.
    std::uint8_t s_bytes[32];
    s.to_bytes_le(s_bytes);

    Element acc = Element::identity();
    Element base = p;

    // Iterate scalar bits LSB->MSB. 256 fixed iterations.
    for (int byte_idx = 0; byte_idx < 32; ++byte_idx) {
        std::uint8_t b = s_bytes[byte_idx];
        for (int bit = 0; bit < 8; ++bit) {
            const std::uint64_t one_or_zero = static_cast<std::uint64_t>((b >> bit) & 1u);
            const std::uint64_t mask = 0ULL - one_or_zero;  // -1 if bit set, 0 otherwise
            // Compute acc + base unconditionally; conditionally select.
            Element sum = Element::add(acc, base);
            cmov(acc, sum, mask);
            // Always double the base.
            base = Element::double_self(base);
        }
    }
    return acc;
}

// ----- Serialization -------------------------------------------------------

void Element::serialize_compressed(std::uint8_t out[32]) const {
    // Affine coordinates.
    Fp affineX, affineY;
    if (Z.is_one()) {
        affineX = X;
        affineY = Y;
    } else {
        Fp zinv = Fp::inv(Z);
        affineX = Fp::mul(X, zinv);
        affineY = Fp::mul(Y, zinv);
    }
    // If Y is not lex-largest, negate X. Per Banderwagon convention this
    // canonicalises the equivalence class { (x,y), (-x,-y) }.
    if (!affineY.lex_largest()) {
        affineX = Fp::neg(affineX);
    }
    affineX.to_bytes_be(out);
}

void Element::serialize_uncompressed(std::uint8_t out[64]) const {
    Fp affineX, affineY;
    if (Z.is_one()) {
        affineX = X;
        affineY = Y;
    } else {
        Fp zinv = Fp::inv(Z);
        affineX = Fp::mul(X, zinv);
        affineY = Fp::mul(Y, zinv);
    }
    affineX.to_bytes_be(out);
    affineY.to_bytes_be(out + 32);
}

// Subgroup check: Banderwagon point with affine x is in the prime subgroup
// iff (1 - a*x^2) is a quadratic residue. (Koshelev, eprint 2022/037.)
namespace {

bool subgroup_check(const Fp& x) {
    const Fp& a_const = curve_a_impl();
    Fp ax2 = Fp::mul(a_const, Fp::square(x));
    Fp r = Fp::sub(Fp::one(), ax2);
    return Fp::legendre(r) == 1;
}

}  // namespace

bool Element::deserialize_compressed(const std::uint8_t bytes[32], Element& out) {
    Fp x;
    if (!Fp::from_bytes_be(bytes, x)) return false;

    // Subgroup membership (rejects bad-subgroup encodings).
    if (!subgroup_check(x)) return false;

    // Recover y from x: y^2 = (a*x^2 - 1) / (d*x^2 - 1).
    const Fp& a_const = curve_a_impl();
    const Fp& d_const = curve_d_impl();
    Fp x2 = Fp::square(x);
    Fp num = Fp::sub(Fp::mul(a_const, x2), Fp::one());
    Fp den = Fp::sub(Fp::mul(d_const, x2), Fp::one());
    if (den.is_zero()) return false;
    Fp y2 = Fp::mul(num, Fp::inv(den));
    Fp y;
    if (!Fp::sqrt(y2, y)) return false;

    // Choose y to be the lex-largest root (Banderwagon convention: encoder
    // negates X iff Y is not lex-largest, so on decode we *take* y as
    // lex-largest, which makes the round-trip a no-op).
    if (!y.lex_largest()) y = Fp::neg(y);

    out.X = x;
    out.Y = y;
    out.Z = Fp::one();
    // Verify: this point really is on the curve (defence in depth).
    if (!out.is_on_curve()) return false;
    return true;
}

bool Element::deserialize_uncompressed(const std::uint8_t bytes[64], Element& out) {
    Fp x, y;
    if (!Fp::from_bytes_be(bytes, x)) return false;
    if (!Fp::from_bytes_be(bytes + 32, y)) return false;

    // Recompute y from x and verify match.
    const Fp& a_const = curve_a_impl();
    const Fp& d_const = curve_d_impl();
    Fp x2 = Fp::square(x);
    Fp num = Fp::sub(Fp::mul(a_const, x2), Fp::one());
    Fp den = Fp::sub(Fp::mul(d_const, x2), Fp::one());
    if (den.is_zero()) return false;
    Fp y2_expected = Fp::mul(num, Fp::inv(den));
    if (!Fp::square(y).equal(y2_expected)) return false;

    // Subgroup check.
    if (!subgroup_check(x)) return false;

    out.X = x;
    out.Y = y;
    out.Z = Fp::one();
    return true;
}

Fp Element::map_to_base_field() const {
    // res = X / Y. (Banderwagon Verkle/Pedersen mapping.)
    if (Y.is_zero()) return Fp::zero();
    return Fp::mul(X, Fp::inv(Y));
}

}  // namespace kinet::banderwagon

// =============================================================================
// extern "C" surface: Element_*  (mirrors Fp_* / Fr_* convention).
// =============================================================================
extern "C" {

using kinet::banderwagon::Element;

void Element_identity(Element* out) { *out = Element::identity(); }
void Element_generator(Element* out) { *out = Element::generator(); }
int  Element_is_identity(const Element* p) { return p->is_identity() ? 1 : 0; }
int  Element_is_on_curve(const Element* p) { return p->is_on_curve() ? 1 : 0; }
int  Element_equal(const Element* p1, const Element* p2) {
    return Element::equal(*p1, *p2) ? 1 : 0;
}
void Element_add(Element* out, const Element* p1, const Element* p2) {
    *out = Element::add(*p1, *p2);
}
void Element_double(Element* out, const Element* p) {
    *out = Element::double_self(*p);
}
void Element_neg(Element* out, const Element* p) {
    *out = Element::neg(*p);
}
void Element_sub(Element* out, const Element* p1, const Element* p2) {
    *out = Element::sub(*p1, *p2);
}
void Element_scalar_mul(Element* out, const Element* p, const kinet::banderwagon::Fr* s) {
    *out = Element::scalar_mul(*p, *s);
}
void Element_serialize_compressed(const Element* p, std::uint8_t out[32]) {
    p->serialize_compressed(out);
}
void Element_serialize_uncompressed(const Element* p, std::uint8_t out[64]) {
    p->serialize_uncompressed(out);
}
int  Element_deserialize_compressed(Element* out, const std::uint8_t bytes[32]) {
    return Element::deserialize_compressed(bytes, *out) ? 1 : 0;
}
int  Element_deserialize_uncompressed(Element* out, const std::uint8_t bytes[64]) {
    return Element::deserialize_uncompressed(bytes, *out) ? 1 : 0;
}
void Element_map_to_base_field(const Element* p, kinet::banderwagon::Fp* out) {
    *out = p->map_to_base_field();
}

}  // extern "C"

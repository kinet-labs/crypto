// SPDX-License-Identifier: Apache-2.0
//
// banderwagon/element.hpp -- Banderwagon group element.
//
// Banderwagon is the prime-order quotient of Bandersnatch by its 2-torsion.
// Bandersnatch is the twisted Edwards curve over Fp = BLS12-381 scalar field
// with parameters
//
//   a = -5,        d = 45022363124591815672509500913686876175488063829319466900776701791074614335719
//
// (The curve is defined by  a*x^2 + y^2 = 1 + d*x^2*y^2  over Fp.) The
// quotient identifies the equivalence class { (x,y), (-x,-y) }, i.e.
// equality is tested via  x1*y2 == y1*x2  in projective coords.
//
// Storage: projective (X : Y : Z) over Fp. Identity is (0 : 1 : 1).
// Generator (X, Y, 1) with X, Y as gnark CurveParams.Base.
//
// Serialization (matches kinet-labs/crypto/ipa/banderwagon Bytes/SetBytes):
//   - Compressed:    32 bytes.  Encodes the affine x-coordinate, sign-flipped
//                    so that y is *not* lexicographically largest.
//                    SetBytes recovers x, then y via  y^2 = (a*x^2 - 1)/(d*x^2 - 1),
//                    rejecting bad-subgroup encodings via the
//                    (1 - a*x^2) Legendre check.
//   - Uncompressed:  64 bytes.  Affine (x, y), each 32-byte big-endian.
//
// First-party. No vendoring. Constant-time scalar multiplication
// (right-to-left double-and-add over the full 256-bit scalar; both branches
// always executed, the result of the conditional add is selected by mask).

#pragma once

#include "fp.hpp"
#include "fr.hpp"

#include <array>
#include <cstdint>

namespace kinet::banderwagon {

// Banderwagon group element in projective (X : Y : Z) coordinates.
struct Element {
    Fp X;
    Fp Y;
    Fp Z;

    // Constructors.
    Element() = default;

    // Constants.
    static Element identity();   // (0 : 1 : 1)
    static Element generator();  // canonical Banderwagon generator (Base of Bandersnatch)

    // Predicates.
    bool is_identity() const;
    bool is_on_curve() const;     // checks   a*x^2 + y^2 == 1 + d*x^2*y^2  (with Z normalisation)

    // Banderwagon equality: identifies (x,y) with (-x,-y).
    // Returns true iff p1 == p2 in the prime-order quotient. False if either
    // operand is the spurious (0,0) point (which is not in the group).
    static bool equal(const Element& p1, const Element& p2);

    // Group operations. Constant-time wrt operand values; both produce a
    // valid projective point. Uses unified twisted-Edwards projective
    // formulas (no special case for P = Q).
    static Element neg(const Element& p);
    static Element add(const Element& p1, const Element& p2);
    static Element double_self(const Element& p);
    static Element sub(const Element& p1, const Element& p2);

    // Constant-time scalar multiplication.  s is the Fr scalar (in Montgomery
    // form). The implementation iterates over the canonical scalar bits and
    // performs both a double and a (masked) add at each step; total operations
    // are independent of `s`.
    static Element scalar_mul(const Element& p, const Fr& s);

    // Serialization.
    //
    // serialize_compressed: write 32-byte canonical encoding (Banderwagon Bytes()).
    // For the identity (0:1:Z), encodes 0 (since x = 0, sign of y = positive).
    void serialize_compressed(std::uint8_t out[32]) const;

    // serialize_uncompressed: write 64-byte (X || Y) affine, big-endian.
    void serialize_uncompressed(std::uint8_t out[64]) const;

    // deserialize_compressed: parse 32-byte form. Returns true on success
    // (point was on curve and in subgroup); false otherwise.
    static bool deserialize_compressed(const std::uint8_t bytes[32], Element& out);

    // deserialize_uncompressed: parse 64-byte form. Performs full on-curve
    // and subgroup checks. Returns true on success.
    static bool deserialize_uncompressed(const std::uint8_t bytes[64], Element& out);

    // map_to_base_field: returns x/y as an Fp element. Used by Verkle/Pedersen.
    // Requires y != 0 (which is true for any non-identity Banderwagon point).
    Fp map_to_base_field() const;
};

// Curve constants (exported for tests / extern callers).
const Fp& curve_a();   // a = -5 (in Montgomery form)
const Fp& curve_d();   // d (in Montgomery form)

}  // namespace kinet::banderwagon

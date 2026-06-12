// =============================================================================
// kinet-labs/crypto/banderwagon -- twisted Edwards group on BLS12-381 Fr
// =============================================================================
//
// Banderwagon is the prime-order subgroup of Bandersnatch (a twisted Edwards
// curve embedded in BLS12-381's scalar field Fr) exposed via the
// "prime-subgroup pair" trick: two affine points (x, y) and (-x, -y) represent
// the same group element, so we serialise x * sign(y) and recover the unique
// representative on deserialisation.
//
// Curve:        -x^2 + y^2 = 1 + d * x^2 * y^2  (Edwards twisted, a = -5)
// Base field:   Fp = BLS12-381 Fr
//                 q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
//               (~ 255-bit prime; this is intentionally NOT BLS12-381's Fp.
//               BLS12-381's Fp is 381-bit and is a different field used for
//               BLS G1/G2/pairing arithmetic.)
// Scalar field: Fr (~ 252-bit) of order
//                 r = 13108968793781547619861935127046491459309155893440570251786403306729687672801
//
// Reference ports:
//   * crate-crypto/go-ipa/banderwagon  (Apache-2.0)
//   * consensys/gnark-crypto/.../bandersnatch  (Apache-2.0)
//   * ethereum/banderwagon-py  (MIT) -- test vector source
//
// =============================================================================

#ifndef CRYPTO_BANDERWAGON_HPP
#define CRYPTO_BANDERWAGON_HPP

#include <array>
#include <cstdint>
#include <cstddef>
#include <string>
#include <intx/intx.hpp>

namespace kinet::crypto::banderwagon {

// =============================================================================
// Field Fp (Banderwagon base field; this is BLS12-381 Fr)
// =============================================================================
//
// The 4-limb little-endian Montgomery form is byte-compatible with
// gnark-crypto's bls12-381/fr.Element. Bytes() of a banderwagon point in the
// Go reference is the little-endian Montgomery output of fp.Element.Bytes(),
// which itself returns the canonical (non-Montgomery) big-endian
// representation. We expose both a canonical (big-endian) and an internal
// Montgomery form here.

class Fp {
public:
    // Canonical modulus q (BLS12-381 Fr). Big-endian bytes:
    //   73 ed a7 53 29 9d 7d 48 33 39 d8 08 09 a1 d8 05
    //   53 bd a4 02 ff fe 5b fe ff ff ff ff 00 00 00 01
    static const intx::uint256 modulus();

    // Constants
    static const Fp& zero();
    static const Fp& one();
    static const Fp& minus_one();

    // ---- Construction --------------------------------------------------------
    Fp() : limbs_{0, 0, 0, 0} {}
    explicit Fp(uint64_t v);
    static Fp from_canonical_be(const uint8_t bytes[32]);  // returns canonical form
    static Fp from_canonical_le(const uint8_t bytes[32]);
    static bool try_from_canonical_be(const uint8_t bytes[32], Fp& out);
    static bool try_from_canonical_le(const uint8_t bytes[32], Fp& out);

    // Static factory from a decimal/hex string. Used for curve-parameter
    // initialization. The input is treated as a canonical integer in [0, q).
    static Fp from_decimal(const std::string& dec);
    static Fp from_hex(const std::string& hex);

    // ---- Serialisation -------------------------------------------------------
    void to_canonical_be(uint8_t out[32]) const;
    void to_canonical_le(uint8_t out[32]) const;

    // ---- Comparison ----------------------------------------------------------
    bool is_zero() const;
    bool is_one() const;
    bool equal(const Fp& o) const;

    // ---- Arithmetic ----------------------------------------------------------
    Fp add(const Fp& o) const;
    Fp sub(const Fp& o) const;
    Fp neg() const;
    Fp mul(const Fp& o) const;
    Fp square() const;
    Fp inverse() const;            // Fermat: a^(q-2). Returns zero on input zero.
    Fp pow(const intx::uint256& exp) const;

    // Multiplies by 5 (used by mulByA = neg + mul5 to apply a = -5).
    Fp mul5() const;

    // Legendre symbol: returns +1 if QR, -1 if NQR, 0 if zero.
    int legendre() const;

    // Square root (Tonelli-Shanks). Returns false if input is non-residue.
    bool sqrt(Fp& out) const;

    // RFC 8032 lex-largest test: x is "negative" iff its canonical big-endian
    // encoding is lexicographically larger than (-x)'s canonical encoding,
    // equivalent to: x > (q - 1) / 2.
    bool lexicographically_largest() const;

    // Internal access (4 x uint64 little-endian limbs).
    const std::array<uint64_t, 4>& limbs() const { return limbs_; }
    std::array<uint64_t, 4>& limbs() { return limbs_; }

private:
    // 4 x 64-bit little-endian limbs, value < q (canonical reduced form).
    // We do NOT store in Montgomery form to keep canonical comparisons cheap;
    // multiplication is done by reducing the 512-bit product modulo q.
    std::array<uint64_t, 4> limbs_;

    static Fp reduce_512(const intx::uint512& x);
};

// =============================================================================
// Field Fr (Banderwagon scalar field; ~252-bit)
// =============================================================================

class Fr {
public:
    // Subgroup order r:
    //   13108968793781547619861935127046491459309155893440570251786403306729687672801
    static const intx::uint256 modulus();

    static const Fr& zero();
    static const Fr& one();

    Fr() : limbs_{0, 0, 0, 0} {}
    explicit Fr(uint64_t v);
    static Fr from_canonical_be(const uint8_t bytes[32]);
    static Fr from_canonical_le(const uint8_t bytes[32]);
    static bool try_from_canonical_be(const uint8_t bytes[32], Fr& out);
    static bool try_from_canonical_le(const uint8_t bytes[32], Fr& out);

    void to_canonical_be(uint8_t out[32]) const;
    void to_canonical_le(uint8_t out[32]) const;

    bool is_zero() const;
    bool equal(const Fr& o) const;

    // Bitwise access used by scalar multiplication (NAF / double-and-add).
    // bit_length returns highest set bit + 1, or 0 if zero.
    size_t bit_length() const;
    bool bit(size_t i) const;

    // Internal limbs.
    const std::array<uint64_t, 4>& limbs() const { return limbs_; }

private:
    std::array<uint64_t, 4> limbs_;
};

// =============================================================================
// Bandersnatch curve parameters
// =============================================================================

struct CurveParams {
    Fp a;        // -5 mod q (twisted Edwards a)
    Fp d;        // 45022363124591815672509500913686876175488063829319466900776701791074614335719
    Fp base_x;   // generator X
    Fp base_y;   // generator Y
};

const CurveParams& curve_params();

// =============================================================================
// PointProj - projective coordinates (X : Y : Z), affine = (X/Z, Y/Z)
// =============================================================================
//
// Identity: (0 : 1 : 1)

struct PointProj {
    Fp X, Y, Z;

    static PointProj identity();
    static PointProj generator();

    bool is_identity() const;
    bool equal_proj(const PointProj& o) const;        // strict equality of (X/Z, Y/Z)
    bool equal_banderwagon(const PointProj& o) const; // Banderwagon: x1*y2 == y1*x2

    PointProj neg() const;
    PointProj add(const PointProj& o) const;
    PointProj dbl() const;
    PointProj sub(const PointProj& o) const;

    // Naive double-and-add scalar multiplication. Constant-time over the
    // declared bit-length, not the underlying scalar value.
    PointProj scalar_mul(const Fr& s) const;

    // Convert to affine (X/Z, Y/Z). Aborts on identity-with-Z=0.
    void to_affine(Fp& x_out, Fp& y_out) const;

    // Curve membership: -x^2 + y^2 == 1 + d * x^2 * y^2 (in projective form).
    bool is_on_curve() const;
};

// =============================================================================
// Element - a Banderwagon group element (prime-order subgroup wrapper)
// =============================================================================

class Element {
public:
    Element() : inner_(PointProj::identity()) {}
    explicit Element(const PointProj& p) : inner_(p) {}

    static Element identity();
    static Element generator();

    // ---- Group operations ----------------------------------------------------
    Element add(const Element& o) const;
    Element sub(const Element& o) const;
    Element dbl() const;
    Element neg() const;
    Element scalar_mul(const Fr& s) const;

    // Banderwagon group equality: (x1, y1) ~ (x2, y2) iff x1*y2 == y1*x2.
    bool equal(const Element& o) const;

    // ---- Encoding (compressed, 32 bytes) ------------------------------------
    //
    // Encode: take affine (x, y); if y is NOT lex-largest, replace x with -x.
    // Then output canonical big-endian bytes of x.
    //
    // Decode: read x; recover y from -x^2 + y^2 = 1 + d x^2 y^2:
    //   y^2 = (a x^2 - 1) / (d x^2 - 1)   with a = -5
    // Subgroup check: (1 - a x^2) must be a quadratic residue.
    //
    // SetBytes performs subgroup check; SetBytesUnsafe does not.
    static constexpr size_t COMPRESSED_SIZE = 32;
    static constexpr size_t UNCOMPRESSED_SIZE = 64;

    void to_bytes(uint8_t out[32]) const;
    bool from_bytes(const uint8_t in[32]);          // performs subgroup check
    bool from_bytes_unsafe(const uint8_t in[32]);   // no subgroup check

    void to_bytes_uncompressed_trusted(uint8_t out[64]) const;
    bool from_bytes_uncompressed(const uint8_t in[64], bool trusted);

    // Map to scalar field via X / Y (used by IPA Fiat-Shamir transcript).
    Fr map_to_scalar_field() const;

    const PointProj& inner() const { return inner_; }

private:
    PointProj inner_;
};

// =============================================================================
// Multi-scalar multiplication
// =============================================================================
//
// Computes sum_i scalars[i] * points[i].
//
// Below crossover_threshold(): naive linear scalar_mul + add (CPU only).
// Above: windowed Pippenger algorithm (CPU; Metal driver in gpu/metal/).

size_t crossover_threshold();

Element msm(const Element* points, const Fr* scalars, size_t n);

// =============================================================================
// Subgroup check
// =============================================================================
// Returns true iff (1 - a*x^2) is a square in Fp, equivalently the point
// belongs to the prime-order subgroup of Bandersnatch.
bool subgroup_check_x(const Fp& x);

}  // namespace kinet::crypto::banderwagon

#endif  // CRYPTO_BANDERWAGON_HPP

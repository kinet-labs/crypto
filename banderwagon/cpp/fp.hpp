// SPDX-License-Identifier: Apache-2.0
//
// banderwagon/fp.hpp -- Bandersnatch base field (= BLS12-381 scalar field).
//
// Modulus q (256 bits, prime, 255-bit):
//   q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
//
// Elements are stored as 4 x u64 little-endian limbs in Montgomery form,
// where R = 2^256 mod q. Inputs to from_bytes_le are 32-byte canonical
// little-endian integers in [0, q); to_bytes_le emits the same canonical form.
//
// First-party authored. No vendoring. Constant-time inner loops:
// no data-dependent branches in add/sub/mul/square/neg. Inverse uses
// Fermat's little theorem (a^(q-2)) with a fixed-window square-and-multiply
// driven by the *constant* exponent q-2; the loop count is fixed (256).
//
// Reference: Y. El Housni & G. Botrel, "Faster Montgomery Multiplication
// and Multi-Scalar-Multiplication for SNARKS",
// https://doi.org/10.46586/tches.v2023.i3.504-521 (Algorithm 2, CIOS).
#pragma once

#include <array>
#include <cstdint>

namespace kinet::banderwagon {

// 4 limbs of 64 bits, little-endian (limbs[0] is least-significant).
struct Fp {
    std::array<std::uint64_t, 4> limbs;

    constexpr Fp() : limbs{0, 0, 0, 0} {}
    constexpr explicit Fp(std::array<std::uint64_t, 4> l) : limbs(l) {}

    // Constants in Montgomery form.
    static Fp zero();
    static Fp one();

    // Predicates (constant-time).
    bool is_zero() const;
    bool is_one() const;
    bool equal(const Fp& other) const;

    // Arithmetic. All inputs/outputs are Montgomery form.
    static Fp add(const Fp& a, const Fp& b);
    static Fp sub(const Fp& a, const Fp& b);
    static Fp neg(const Fp& a);
    static Fp mul(const Fp& a, const Fp& b);
    static Fp square(const Fp& a);

    // Inverse. Returns zero() if a == zero(); otherwise a^(q-2) (== a^-1).
    static Fp inv(const Fp& a);

    // Codec. Bytes are 32-byte canonical little-endian integer in [0, q).
    // from_bytes_le returns true on success; false if the encoded value is
    // >= q (in which case `out` is left unchanged).
    static bool from_bytes_le(const std::uint8_t bytes[32], Fp& out);
    void to_bytes_le(std::uint8_t bytes[32]) const;

    // Big-endian variants matching gnark-crypto's Element.Bytes(), which
    // emits the canonical integer in *big-endian* order. Banderwagon
    // group encodings (Bytes/SetBytes) use this order.
    static bool from_bytes_be(const std::uint8_t bytes[32], Fp& out);
    void to_bytes_be(std::uint8_t bytes[32]) const;

    // Tonelli-Shanks square root. Returns true and writes a root to `out`
    // iff `a` is a quadratic residue (or zero). The returned root is the
    // *non-largest* one (per `lex_largest`).
    static bool sqrt(const Fp& a, Fp& out);

    // Legendre symbol: -1 (non-residue), 0 (zero), 1 (residue).
    static int legendre(const Fp& a);

    // Lexicographically-largest predicate: true iff the canonical integer
    // value is strictly greater than (q-1)/2. Matches gnark
    // Element.LexicographicallyLargest semantics.
    bool lex_largest() const;
};

}  // namespace kinet::banderwagon

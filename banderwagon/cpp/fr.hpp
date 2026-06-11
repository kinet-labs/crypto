// SPDX-License-Identifier: Apache-2.0
//
// banderwagon/fr.hpp -- Bandersnatch scalar field.
//
// Modulus r (256 bits, prime, 253-bit):
//   r = 0x1cfb69d4ca675f520cce760202687600ff8f87007419047174fd06b52876e7e1
//     = 13108968793781547619861935127046491459309155893440570251786403306729687672801
//
// Elements are stored as 4 x u64 little-endian limbs in Montgomery form,
// where R = 2^256 mod r. Inputs to from_bytes_le are 32-byte canonical
// little-endian integers in [0, r); to_bytes_le emits the same canonical form.
//
// First-party authored. No vendoring. Constant-time inner loops:
// no data-dependent branches in add/sub/mul/square/neg. Inverse uses
// Fermat's little theorem (a^(r-2)) with a fixed-window square-and-multiply
// driven by the *constant* exponent r-2; the loop count is fixed (256).
//
// Reference: Y. El Housni & G. Botrel, "Faster Montgomery Multiplication
// and Multi-Scalar-Multiplication for SNARKS",
// https://doi.org/10.46586/tches.v2023.i3.504-521 (Algorithm 2, CIOS).
#pragma once

#include <array>
#include <cstdint>

namespace kinet::banderwagon {

// 4 limbs of 64 bits, little-endian (limbs[0] is least-significant).
struct Fr {
    std::array<std::uint64_t, 4> limbs;

    constexpr Fr() : limbs{0, 0, 0, 0} {}
    constexpr explicit Fr(std::array<std::uint64_t, 4> l) : limbs(l) {}

    // Constants in Montgomery form.
    static Fr zero();
    static Fr one();

    // Predicates (constant-time).
    bool is_zero() const;
    bool is_one() const;
    bool equal(const Fr& other) const;

    // Arithmetic. All inputs/outputs are Montgomery form.
    static Fr add(const Fr& a, const Fr& b);
    static Fr sub(const Fr& a, const Fr& b);
    static Fr neg(const Fr& a);
    static Fr mul(const Fr& a, const Fr& b);
    static Fr square(const Fr& a);

    // Inverse. Returns zero() if a == zero(); otherwise a^(r-2) (== a^-1).
    static Fr inv(const Fr& a);

    // Codec. Bytes are 32-byte canonical little-endian integer in [0, r).
    // from_bytes_le returns true on success; false if the encoded value is
    // >= r (in which case `out` is left unchanged).
    static bool from_bytes_le(const std::uint8_t bytes[32], Fr& out);
    void to_bytes_le(std::uint8_t bytes[32]) const;
};

}  // namespace kinet::banderwagon

// First-party optimal-ate pairing for bn254 (alt_bn128).
//
//   Miller loop:        f_{6x+2,Q}(P) over Fp12
//   Final exponent:     (p^12 - 1) / r decomposed as
//                       (p^6 - 1)(p^2 + 1)(p^4 - p^2 + 1)/r,
//                       with the hard part computed via Fuentes-Castaneda
//                       (Duquesne-Ghammam eprint 2015/192) with
//                       cyclotomic squares.
//
//   Curve seed:         x = 4965661367192848881
//   Loop counter:       6x + 2 = 29793968203157093288 (NAF, 65 bits)
//
// The implementation only depends on the first-party Fp / Fp2 / Fp6 / Fp12
// tower and on G1 / G2 in the same directory. No upstream library is
// vendored.

#pragma once

#include "bn254_fp12.hpp"
#include "bn254_g1.hpp"
#include "bn254_g2.hpp"

#include <cstddef>

namespace kinet::crypto::bn254 {

// Compute the multi-pairing product
//   prod_i e(P_i, Q_i)
// and return the result in GT = Fp12.
//
// All P[i] and Q[i] inputs are expected to be on-curve and in their
// respective subgroups (callers validate via g1_is_on_curve / g2_is_on_curve).
// Infinity points are allowed and skipped.
Fp12 multi_miller_loop(const G1Affine* P, const G2Affine* Q, std::size_t n) noexcept;

// Final exponentiation of an Fp12 element to (p^12 - 1)/r.
Fp12 final_exponentiation(const Fp12& f) noexcept;

// One-shot multi-pairing: product of all pairings, final-exponentiated.
Fp12 multi_pair(const G1Affine* P, const G2Affine* Q, std::size_t n) noexcept;

// Predicate form -- returns true iff the multi-pairing equals 1 in GT.
bool multi_pairing_check(const G1Affine* P, const G2Affine* Q, std::size_t n) noexcept;

// Granger-Scott cyclotomic squaring on an Fp12 element from the cyclotomic
// subgroup (i.e. unitary, conj == inv). Inputs that aren't unitary will not
// match the optimised square -- the GPU determinism harness only feeds
// post-final-exp-easy-part Fp12 values to this routine.
Fp12 cyclotomic_sqr_public(const Fp12& x) noexcept;

}  // namespace kinet::crypto::bn254

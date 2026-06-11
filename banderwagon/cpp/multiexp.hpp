// SPDX-License-Identifier: Apache-2.0
//
// banderwagon/multiexp.hpp -- Pippenger Multi-Scalar-Multiplication.
//
// Computes  R = sum_{i} scalars[i] * elements[i]   in the Banderwagon group.
//
// Algorithm: signed-digit Pippenger (gnark-crypto / Bos-Coster bucket method,
// section 4 of https://eprint.iacr.org/2012/549.pdf, identical strategy as
// kinet-labs/crypto/ipa/bandersnatch/multiexp.go).
//
//   1. Auto-tune window size c in [4, 16] based on N.
//   2. For each c-bit window w over the scalar (LSW->MSW), partition each
//      scalar into a signed digit in (-2^{c-1}, 2^{c-1}]. A digit > 2^{c-1}
//      borrows 2^c from the next window and becomes negative.
//      This halves the bucket count from 2^c to 2^{c-1}.
//   3. Per window: place each (signed) digit into one of 2^{c-1} buckets
//      (negative digits add the negation of the point).
//   4. Reduce buckets to a window-sum via the running-sum trick:
//        total = sum_{k=1..M} k * bucket[k]
//      done in 2*(M-1) group additions instead of O(M^2) doublings.
//   5. Combine window sums from MSW to LSW:
//        result = (((W_{n-1} * 2^c) + W_{n-2}) * 2^c + ...) + W_0
//
// Variable-time. Standard for *verifier-side* MSM. The scalar-window digit
// values gate the bucket index and the sign of the addend; this is *not*
// constant-time and SHOULD NOT be used to operate on secret scalars.
// (For secret scalars, use Element::scalar_mul on each (e_i, s_i) pair and
// sum the results.)
//
// First-party. No vendoring.
//
// API:
//   Element multi_scalar_mul(const Element*, const Fr*, size_t);
//
// Edge cases (matches Go gnark/banderwagon semantics):
//   - n == 0           -> identity.
//   - n == 1           -> reduces to Element::scalar_mul(elements[0], scalars[0]).
//   - all scalars == 0 -> identity.

#pragma once

#include "element.hpp"
#include "fr.hpp"

#include <cstddef>
#include <cstdint>

namespace kinet::banderwagon {

// VARIABLE-TIME. Pippenger window method branches on scalar digit.
// SAFE for verifier-side use (public scalars).
// UNSAFE for prover-side use with secret scalars (cache side-channel
// can recover scalar via Flush+Reload).
//
// Callers MUST NOT pass secret blinding factors here without scalar-blinding
// (multiplicative randomization) or constant-time alternative.
//
// Constant-time MSM is tracked at LP-137-FOLLOWUP-CT-MSM (TODO).
//
// Compute the multi-scalar-multiplication
//   sum_{i=0..n-1}  scalars[i] * elements[i]
// in the Banderwagon group.
//
// Caller MUST pass equal-length arrays of length `n`.
Element multi_scalar_mul(const Element* elements,
                         const Fr* scalars,
                         std::size_t n);

}  // namespace kinet::banderwagon

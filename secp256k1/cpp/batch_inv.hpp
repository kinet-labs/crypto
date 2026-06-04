// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Montgomery batch inversion for secp256k1 base field (Fp) and scalar field (Fn).
//
// Given inputs z_0, z_1, ..., z_{n-1} compute all z_i^{-1} with one field
// inversion plus 2(n-1) field multiplications (vs n inversions naive). For
// secp256k1 each inversion is ~256 squarings + ~128 multiplies via Fermat;
// batch inversion turns batches of k signatures into one inversion + 3k mults.
//
// Algorithm (Henry Cohen, "A Course in Computational Algebraic Number Theory",
// §10.3.1; also Knuth TAOCP vol 2):
//
//   forward:  p_0 = z_0; p_i = p_{i-1} * z_i      for i = 1..n-1
//   single:   inv = p_{n-1}^{-1}                  (one Fermat exponentiation)
//   backward: out_{n-1} = inv * p_{n-2}
//             inv = inv * z_{n-1}
//             out_{n-2} = inv * p_{n-3}
//             ...
//             out_0 = inv
//
// Inputs/outputs are in Montgomery form. Caller must ensure no z_i is zero;
// if any is zero, this routine signals via the return bitmap (output[i] left
// untouched and bit set on the zero-mask).

#pragma once

#include "field.hpp"

#include <cstdint>
#include <cstddef>
#include <vector>

namespace kinet::crypto::secp256k1 {

// Batch invert n elements of Fp (Montgomery form).
// Returns a bitmap (one bit per input, packed little-endian) of zeros found.
// When zero_mask bit i is 1, out[i] is left as zero.
inline void batch_inv_fp(size_t n, const U256* in, U256* out, uint8_t* zero_mask) {
    if (n == 0) return;

    // Find non-zero entries; cumulate prefix products of non-zero z_i in
    // a temporary array. We index zeros via the mask so the chain stays sparse.
    std::vector<U256> prefix(n);
    std::vector<size_t> live_idx;
    live_idx.reserve(n);

    for (size_t i = 0; i < n; ++i) {
        if (in[i].is_zero()) {
            if (zero_mask) zero_mask[i / 8] |= (uint8_t)(1u << (i & 7));
            out[i] = U256{};
            continue;
        }
        if (live_idx.empty()) {
            prefix[i] = in[i];
        } else {
            prefix[i] = fp_mul(prefix[live_idx.back()], in[i]);
        }
        live_idx.push_back(i);
    }

    if (live_idx.empty()) return;

    // Single inversion of last live prefix.
    U256 inv = fp_inv(prefix[live_idx.back()]);

    // Backward sweep over live indices only.
    for (size_t k = live_idx.size(); k-- > 1; ) {
        size_t cur = live_idx[k];
        size_t prev = live_idx[k - 1];
        out[cur] = fp_mul(inv, prefix[prev]);
        inv = fp_mul(inv, in[cur]);
    }
    // First live index gets the running inverse directly.
    out[live_idx[0]] = inv;
}

// Same as batch_inv_fp but over the scalar field Fn.
inline void batch_inv_fn(size_t n, const U256* in, U256* out, uint8_t* zero_mask) {
    if (n == 0) return;

    std::vector<U256> prefix(n);
    std::vector<size_t> live_idx;
    live_idx.reserve(n);

    for (size_t i = 0; i < n; ++i) {
        if (in[i].is_zero()) {
            if (zero_mask) zero_mask[i / 8] |= (uint8_t)(1u << (i & 7));
            out[i] = U256{};
            continue;
        }
        if (live_idx.empty()) {
            prefix[i] = in[i];
        } else {
            prefix[i] = fn_mul(prefix[live_idx.back()], in[i]);
        }
        live_idx.push_back(i);
    }

    if (live_idx.empty()) return;

    U256 inv = fn_inv(prefix[live_idx.back()]);

    for (size_t k = live_idx.size(); k-- > 1; ) {
        size_t cur = live_idx[k];
        size_t prev = live_idx[k - 1];
        out[cur] = fn_mul(inv, prefix[prev]);
        inv = fn_mul(inv, in[cur]);
    }
    out[live_idx[0]] = inv;
}

}  // namespace kinet::crypto::secp256k1

// SPDX-License-Identifier: Apache-2.0
//
// banderwagon/multiexp.cpp -- Pippenger MSM (variable-time).
//
// Mirrors kinet-labs/crypto/ipa/bandersnatch/multiexp.go (section 4 of
// https://eprint.iacr.org/2012/549.pdf), with the Banderwagon group ops
// from element.cpp.
//
// Window size c ∈ [4, 16] is selected by minimising the cost model
//   cost(c) = (256/c) * (N + 2^c)         (group ops; see Go reference).
//
// For each c-bit window w (0..nbChunks-1), digits are signed:
//   digit ∈ [-2^{c-1}, 2^{c-1}]
// produced by sweeping LSW->MSW with a borrow carry. Negative digit -d
// adds (-P) into bucket[d-1]; positive digit +d adds (P) into bucket[d-1].
// Bucket count is M = 2^{c-1}.
//
// The window sum is reduced from M buckets via a single running-sum sweep
// (k = M-1 downto 0): runningSum += bucket[k]; total += runningSum;
// so total = 1*B[0] + 2*B[1] + ... + M*B[M-1]   in 2*(M-1) ops (no doublings).
//
// The final combiner walks windows from MSW to LSW, doubling c times
// between each.

#include "multiexp.hpp"

#include "element.hpp"
#include "fr.hpp"

#include <cstdint>
#include <limits>
#include <vector>

namespace kinet::banderwagon {

namespace {

// Cost-minimising c selection (matches Go reference, capped at 16).
std::uint64_t best_c(std::size_t n) {
    constexpr double bits = 256.0;
    static const std::uint64_t implementedCs[] = {4, 5, 6, 7, 8, 9, 10, 11,
                                                  12, 13, 14, 15, 16};
    double min = std::numeric_limits<double>::infinity();
    std::uint64_t best = 4;
    for (std::uint64_t c : implementedCs) {
        const double pow2c = static_cast<double>(1ULL << c);
        const double cost = (bits / static_cast<double>(c)) *
                            (static_cast<double>(n) + pow2c);
        if (cost < min) {
            min = cost;
            best = c;
        }
    }
    return best;
}

// Read a c-bit unsigned digit from a 32-byte LE canonical scalar buffer at
// the given bit offset. Bits beyond the scalar are treated as zero.
inline std::uint32_t window_digit(const std::uint8_t* s_le,
                                  std::size_t bit_offset,
                                  std::uint64_t c) {
    const std::size_t byte_idx = bit_offset >> 3;
    const std::size_t bit_in_byte = bit_offset & 7;

    // 4 bytes is enough for any c ≤ 16 plus 7-bit straddle.
    std::uint32_t word = 0;
    for (int i = 0; i < 4; ++i) {
        const std::size_t bi = byte_idx + i;
        if (bi < 32) {
            word |= static_cast<std::uint32_t>(s_le[bi]) << (8 * i);
        }
    }
    word >>= bit_in_byte;

    const std::uint32_t mask = (1u << c) - 1u;
    return word & mask;
}

// Process one window: signed-digit partition + bucket accumulate +
// running-sum reduction. `carries[i]` is the borrow into the *next* call.
Element process_window(const Element* elements,
                       const std::uint8_t* scalars_le,  // [n][32]
                       std::size_t n,
                       std::size_t bit_offset,
                       std::uint64_t c,
                       std::vector<Element>& buckets,
                       std::vector<int>& carries) {
    const std::int32_t max_pos_digit = static_cast<std::int32_t>(1u << (c - 1));
    const std::size_t M = static_cast<std::size_t>(1u) << (c - 1);

    for (std::size_t k = 0; k < M; ++k) {
        buckets[k] = Element::identity();
    }

    for (std::size_t i = 0; i < n; ++i) {
        std::uint32_t bits = window_digit(scalars_le + 32 * i, bit_offset, c);

        std::int32_t digit = static_cast<std::int32_t>(bits) + carries[i];
        carries[i] = 0;

        if (digit == 0) continue;

        // Signed-digit normalise: if digit > 2^{c-1}, borrow 2^c and negate.
        if (digit > max_pos_digit) {
            digit -= static_cast<std::int32_t>(1u << c);
            carries[i] = 1;
        }

        if (digit > 0) {
            const std::size_t k = static_cast<std::size_t>(digit) - 1;
            buckets[k] = Element::add(buckets[k], elements[i]);
        } else if (digit < 0) {
            const std::size_t k = static_cast<std::size_t>(-digit) - 1;
            buckets[k] = Element::add(buckets[k], Element::neg(elements[i]));
        }
        // digit == 0 (only possible when raw bits == 0 and carry == 0,
        // already caught above) -- never falls here.
    }

    // Running-sum reduction (k = M-1 downto 0).
    Element running = Element::identity();
    Element total   = Element::identity();
    for (std::size_t k_inv = 0; k_inv < M; ++k_inv) {
        const std::size_t k = M - 1 - k_inv;
        running = Element::add(running, buckets[k]);
        total   = Element::add(total, running);
    }
    return total;
}

}  // namespace

Element multi_scalar_mul(const Element* elements,
                         const Fr* scalars,
                         std::size_t n) {
    if (n == 0) {
        return Element::identity();
    }
    if (n == 1) {
        return Element::scalar_mul(elements[0], scalars[0]);
    }

    // Convert all scalars to 32-byte LE canonical form.
    std::vector<std::uint8_t> scalars_le(static_cast<std::size_t>(n) * 32);
    for (std::size_t i = 0; i < n; ++i) {
        scalars[i].to_bytes_le(&scalars_le[32 * i]);
    }

    const std::uint64_t c = best_c(n);
    const std::size_t M = static_cast<std::size_t>(1u) << (c - 1);
    const std::size_t nbChunks = (256 + c - 1) / c;  // ceil(256 / c)

    std::vector<Element> buckets(M);
    std::vector<int> carries(n, 0);
    std::vector<Element> window_sums(nbChunks);

    for (std::size_t w = 0; w < nbChunks; ++w) {
        const std::size_t bit_offset = w * static_cast<std::size_t>(c);
        window_sums[w] = process_window(
            elements, scalars_le.data(), n, bit_offset, c, buckets, carries);
    }

    // Combine windows MSW -> LSW with c doublings between each.
    Element result = window_sums[nbChunks - 1];
    for (std::size_t w_inv = 1; w_inv < nbChunks; ++w_inv) {
        for (std::uint64_t b = 0; b < c; ++b) {
            result = Element::double_self(result);
        }
        const std::size_t w = nbChunks - 1 - w_inv;
        result = Element::add(result, window_sums[w]);
    }

    return result;
}

}  // namespace kinet::banderwagon

// =============================================================================
// extern "C" surface.
// =============================================================================
extern "C" {

using kinet::banderwagon::Element;
using kinet::banderwagon::Fr;

// Compute  out = sum_{i=0..n-1}  scalars[i] * elements[i].
// Caller-supplied arrays must each have length `n`.
void Element_multi_scalar_mul(Element* out,
                              const Element* elements,
                              const Fr* scalars,
                              std::size_t n) {
    *out = kinet::banderwagon::multi_scalar_mul(elements, scalars, n);
}

}  // extern "C"

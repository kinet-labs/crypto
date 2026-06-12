// Variable-width Karatsuba (n^log2(3) ≈ n^1.585) for unsigned big integers
// stored as little-endian uint64_t limb arrays. Recursive: splits at half on
// each level, falls back to O(n^2) schoolbook at KARATSUBA_THRESHOLD limbs.
//
// Contract:
//   kmul(r, x, y)
//     * r.size() == x.size() + y.size()  (full product, no truncation)
//     * x.size() == y.size()             (caller equal-pads)
//     * r must not alias x or y
//
// For unequal-size operands the caller schoolbook-multiplies; Karatsuba is
// only worthwhile at large equal widths (≥ 16 limbs = 1024 bits).
//
// Constant-time: control flow is data-independent (all branches depend only
// on operand size, not values). Memory access pattern is fixed per-size.

#pragma once
#include <cstdint>
#include <span>

namespace cevm::crypto::karatsuba
{
/// Threshold (in 64-bit limbs) at which kmul falls back to schoolbook.
/// Calibrated empirically: 4 limbs = 256 bits is small enough that the
/// recursion overhead exceeds the asymptotic win.
inline constexpr size_t THRESHOLD = 4;

/// Multi-precision multiply: r[] = x[] * y[].
/// Requirements:
///   r.size() == x.size() + y.size()
///   x.size() == y.size()
///   r does not alias x or y
/// At sizes < THRESHOLD limbs this delegates to schoolbook. Above, recursive
/// Karatsuba splits into 3 half-sized sub-products with a final fix-up add.
void kmul(std::span<uint64_t> r,
          std::span<const uint64_t> x,
          std::span<const uint64_t> y) noexcept;

/// Variant for callers with unequal operand widths. Pads the shorter operand
/// with zero limbs and dispatches to kmul. Used by modexp's mul() to handle
/// the truncating-product paths uniformly.
///   r.size() >= x.size() + y.size()
void kmul_unequal(std::span<uint64_t> r,
                  std::span<const uint64_t> x,
                  std::span<const uint64_t> y) noexcept;

}  // namespace cevm::crypto::karatsuba

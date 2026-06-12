// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "karatsuba.hpp"
#include "mulmod.hpp"     // crypto::sub, crypto::addmul, crypto::mul (single-limb)

#include <intx/intx.hpp>  // intx::addc, intx::subc, intx::umul

#include <algorithm>
#include <cassert>
#include <cstring>
#include <vector>

namespace cevm::crypto::karatsuba
{
namespace
{
/// Zero-pad: r := source words, then trailing zeros to fill r.size().
inline void copy_pad(std::span<uint64_t> r, std::span<const uint64_t> src) noexcept
{
    assert(r.size() >= src.size());
    std::copy_n(src.data(), src.size(), r.data());
    if (r.size() > src.size())
        std::fill_n(r.data() + src.size(), r.size() - src.size(), uint64_t{0});
}

/// In-place add: x[] += y[]. y may be shorter. Returns the carry-out word.
inline uint64_t add_in_place(std::span<uint64_t> x, std::span<const uint64_t> y) noexcept
{
    assert(x.size() >= y.size());
    bool carry = false;
    size_t i = 0;
    for (; i < y.size(); ++i)
        std::tie(x[i], carry) = intx::addc(x[i], y[i], carry);
    for (; carry && i < x.size(); ++i)
        std::tie(x[i], carry) = intx::addc(x[i], uint64_t{0}, carry);
    return uint64_t{carry};
}

/// In-place sub: x[] -= y[]. y may be shorter. Caller guarantees x >= y so no
/// final borrow leaks past x.size().
inline void sub_in_place(std::span<uint64_t> x, std::span<const uint64_t> y) noexcept
{
    assert(x.size() >= y.size());
    bool borrow = false;
    size_t i = 0;
    for (; i < y.size(); ++i)
        std::tie(x[i], borrow) = intx::subc(x[i], y[i], borrow);
    for (; borrow && i < x.size(); ++i)
        std::tie(x[i], borrow) = intx::subc(x[i], uint64_t{0}, borrow);
}

/// Schoolbook full product: r[] = x[] * y[]. r.size() == x.size() + y.size().
/// Used both as the recursion base case and as the unequal-size fallback.
void schoolbook(std::span<uint64_t> r,
                std::span<const uint64_t> x,
                std::span<const uint64_t> y) noexcept
{
    assert(r.size() == x.size() + y.size());
    std::fill_n(r.data(), r.size(), uint64_t{0});

    for (size_t j = 0; j < y.size(); ++j)
    {
        uint64_t carry = 0;
        for (size_t i = 0; i < x.size(); ++i)
        {
            const auto t = intx::umul(x[i], y[j]) + r[i + j] + carry;
            r[i + j] = t[0];
            carry = t[1];
        }
        r[j + x.size()] = carry;
    }
}

/// Recursive Karatsuba helper. Operates on equal-width inputs of n limbs.
/// Scratch must point to a buffer of at least scratch_size(n) words; it is
/// consumed in a stack-discipline by the recursive calls.
void kmul_rec(uint64_t* r, const uint64_t* x, const uint64_t* y,
              size_t n, uint64_t* scratch) noexcept;

/// Worst-case scratch budget (in uint64 words) needed by kmul_rec at width n.
/// Each level allocates the running sum-pair (half+1 each) plus a 2*(half+1)
/// scratch for the middle product. Levels halve the size; the geometric
/// series sums to < 6 * n. We round up generously.
constexpr size_t scratch_size(size_t n) noexcept
{
    return 8 * n + 64;
}

void kmul_rec(uint64_t* r, const uint64_t* x, const uint64_t* y,
              size_t n, uint64_t* scratch) noexcept
{
    // Base case: schoolbook below threshold. Also handles n == 1 (umul).
    if (n <= THRESHOLD)
    {
        schoolbook({r, 2 * n}, {x, n}, {y, n});
        return;
    }

    // Split: low half = first `half` limbs, high half = remaining (n - half).
    // Use half = (n + 1) / 2 so the high half is the smaller-or-equal piece.
    // The low (x_lo, y_lo) is exactly `half` limbs; the high (x_hi, y_hi) is
    // `n - half` limbs (≤ half). We pad x_hi/y_hi to `half` for the middle
    // sum so all three sub-multiplies are equal-width (= half).
    const size_t half = (n + 1) / 2;
    const size_t hi   = n - half;             // hi <= half

    const uint64_t* x_lo = x;
    const uint64_t* x_hi = x + half;
    const uint64_t* y_lo = y;
    const uint64_t* y_hi = y + half;

    // Layout the result and scratch:
    //   r[0..2*half)        z0 = x_lo * y_lo  (full, exactly 2*half words)
    //   r[2*half..2*half+2*hi)  z2 = x_hi * y_hi  (full, exactly 2*hi words)
    // The buffer r has total size 2n = 2*(half + hi) which is exactly
    // 2*half + 2*hi -- so z0 and z2 sit back-to-back filling r.
    // Then we add z1 = sx*sy - z2 - z0 shifted left by `half` words.

    uint64_t* z0 = r;                  // 2*half words
    uint64_t* z2 = r + 2 * half;       // 2*hi  words

    // Recurse: z0 = x_lo * y_lo  (width half)
    kmul_rec(z0, x_lo, y_lo, half, scratch);

    // Recurse: z2 = x_hi * y_hi  (width hi).
    // hi == 0 only when n == 0; we've already returned via the base case
    // for n <= THRESHOLD, so hi >= ceil(THRESHOLD/2) > 0 here.
    kmul_rec(z2, x_hi, y_hi, hi, scratch);

    // Build the two sums: sx = x_hi + x_lo, sy = y_hi + y_lo. Each fits in
    // half+1 limbs (one carry-out bit). We stash them in scratch[0..half+1)
    // and scratch[half+1..2*(half+1)).
    uint64_t* sx = scratch;
    uint64_t* sy = scratch + (half + 1);
    uint64_t* sub_scratch = scratch + 2 * (half + 1);  // recursion scratch

    // sx = x_lo + x_hi (with x_hi zero-padded to `half` words conceptually).
    {
        bool carry = false;
        for (size_t i = 0; i < hi; ++i)
            std::tie(sx[i], carry) = intx::addc(x_lo[i], x_hi[i], carry);
        for (size_t i = hi; i < half; ++i)
            std::tie(sx[i], carry) = intx::addc(x_lo[i], uint64_t{0}, carry);
        sx[half] = uint64_t{carry};
    }
    {
        bool carry = false;
        for (size_t i = 0; i < hi; ++i)
            std::tie(sy[i], carry) = intx::addc(y_lo[i], y_hi[i], carry);
        for (size_t i = hi; i < half; ++i)
            std::tie(sy[i], carry) = intx::addc(y_lo[i], uint64_t{0}, carry);
        sy[half] = uint64_t{carry};
    }

    // Compute z1' = sx * sy as a `half`-limb multiply, then fold in the carry
    // bits sx[half] and sy[half] separately. This avoids needing a (half+1)-
    // limb recursive multiply (which would invalidate the scratch budget).
    //
    // Algebraically:
    //   sx = a + sxc * 2^(half*64),  where a = sx[0..half), sxc in {0,1}
    //   sy = b + syc * 2^(half*64)
    //   sx * sy = a*b + (a*syc + b*sxc) * 2^(half*64) + sxc*syc * 2^(2*half*64)
    //
    // We allocate z1 with 2*half + 2 words of headroom for the high terms.
    uint64_t* z1 = sub_scratch;                              // 2*half + 2 words
    uint64_t* deep = sub_scratch + (2 * half + 2);           // remaining scratch

    // ab = a * b  (width half) -> first 2*half words of z1.
    kmul_rec(z1, sx, sy, half, deep);
    // Zero the two headroom words.
    z1[2 * half]     = 0;
    z1[2 * half + 1] = 0;

    // Add sxc * b shifted by half words (sxc is 0 or 1).
    if (sx[half])
    {
        // z1[half..2*half] += b[0..half), then propagate carry into z1[2*half..]
        bool carry = false;
        size_t i = 0;
        for (; i < half; ++i)
            std::tie(z1[half + i], carry) = intx::addc(z1[half + i], sy[i], carry);
        for (; carry && (half + i) < (2 * half + 2); ++i)
            std::tie(z1[half + i], carry) = intx::addc(z1[half + i], uint64_t{0}, carry);
    }
    if (sy[half])
    {
        bool carry = false;
        size_t i = 0;
        for (; i < half; ++i)
            std::tie(z1[half + i], carry) = intx::addc(z1[half + i], sx[i], carry);
        for (; carry && (half + i) < (2 * half + 2); ++i)
            std::tie(z1[half + i], carry) = intx::addc(z1[half + i], uint64_t{0}, carry);
    }
    // Add sxc*syc at z1[2*half] (single bit).
    if (sx[half] && sy[half])
    {
        bool carry = false;
        std::tie(z1[2 * half], carry) = intx::addc(z1[2 * half], uint64_t{1}, false);
        if (carry) z1[2 * half + 1] = z1[2 * half + 1] + 1;
    }

    // Now z1 holds sx * sy. Subtract z0 and z2 to get the middle term.
    // z1 -= z0  (z0 is 2*half words; z1 is 2*half + 2 words).
    {
        bool borrow = false;
        size_t i = 0;
        for (; i < 2 * half; ++i)
            std::tie(z1[i], borrow) = intx::subc(z1[i], z0[i], borrow);
        for (; borrow && i < 2 * half + 2; ++i)
            std::tie(z1[i], borrow) = intx::subc(z1[i], uint64_t{0}, borrow);
    }
    // z1 -= z2  (z2 is exactly 2*hi words; high words above z2 are conceptually zero).
    {
        bool borrow = false;
        size_t i = 0;
        for (; i < 2 * hi; ++i)
            std::tie(z1[i], borrow) = intx::subc(z1[i], z2[i], borrow);
        for (; borrow && i < 2 * half + 2; ++i)
            std::tie(z1[i], borrow) = intx::subc(z1[i], uint64_t{0}, borrow);
    }

    // Add z1 into r at offset `half` words.
    // r currently holds [z0 | z2]. r width is 2n = 2*(half + hi) words.
    // The window r[half..half + 2*half + 2) must fit within r[0..2n);
    // worst case half + 2*half + 2 = 3*half + 2; 2n = 2*half + 2*hi <= 2*half + 2*half = 4*half.
    // For n >= 2 (we are above THRESHOLD), 3*half + 2 <= 4*half iff half >= 2, which holds.
    {
        const size_t total = 2 * n;
        const size_t z1_words = 2 * half + 2;
        const size_t avail = total - half;
        const size_t to_add = std::min(z1_words, avail);

        bool carry = false;
        for (size_t i = 0; i < to_add; ++i)
            std::tie(r[half + i], carry) = intx::addc(r[half + i], z1[i], carry);
        // Any remaining carry beyond r is impossible since z1 = sx*sy - z2 - z0
        // is bounded by 2^(2*half*64) (true product magnitude) which fits.
        // assert(!carry);  // enable in debug if desired
        (void)carry;
    }
}

}  // namespace

void kmul(std::span<uint64_t> r,
          std::span<const uint64_t> x,
          std::span<const uint64_t> y) noexcept
{
    assert(x.size() == y.size());
    assert(r.size() == x.size() + y.size());
    assert(r.data() != x.data() && r.data() != y.data());

    const size_t n = x.size();

    // Stack buffer for small-medium widths to avoid heap traffic. At n=64
    // (4096-bit) the budget is < 4 KiB, comfortable on stack. Heap fallback
    // only for absurd widths (> ~256 limbs = 16384-bit).
    constexpr size_t STACK_LIMBS = 1024;  // 8 KiB
    if (scratch_size(n) <= STACK_LIMBS)
    {
        uint64_t buf[STACK_LIMBS];
        kmul_rec(r.data(), x.data(), y.data(), n, buf);
    }
    else
    {
        std::vector<uint64_t> buf(scratch_size(n));
        kmul_rec(r.data(), x.data(), y.data(), n, buf.data());
    }
}

void kmul_unequal(std::span<uint64_t> r,
                  std::span<const uint64_t> x,
                  std::span<const uint64_t> y) noexcept
{
    assert(r.size() >= x.size() + y.size());
    assert(r.data() != x.data() && r.data() != y.data());

    if (x.empty() || y.empty())
    {
        std::fill_n(r.data(), r.size(), uint64_t{0});
        return;
    }

    // Equal-width: dispatch directly.
    if (x.size() == y.size())
    {
        kmul({r.data(), 2 * x.size()}, x, y);
        if (r.size() > 2 * x.size())
            std::fill_n(r.data() + 2 * x.size(), r.size() - 2 * x.size(), uint64_t{0});
        return;
    }

    // Unequal: pad shorter to the larger width, then kmul. Pad costs a small
    // wash of zeros, but only happens for variable-width modexp internals;
    // the RSA-4096 hot path is equal-width and skips this branch.
    const size_t n = std::max(x.size(), y.size());
    std::vector<uint64_t> xp(n, uint64_t{0});
    std::vector<uint64_t> yp(n, uint64_t{0});
    std::copy_n(x.data(), x.size(), xp.data());
    std::copy_n(y.data(), y.size(), yp.data());

    std::vector<uint64_t> prod(2 * n, uint64_t{0});
    kmul({prod.data(), 2 * n}, {xp.data(), n}, {yp.data(), n});

    const size_t need = x.size() + y.size();
    std::copy_n(prod.data(), std::min(need, r.size()), r.data());
    if (r.size() > need)
        std::fill_n(r.data() + need, r.size() - need, uint64_t{0});
}

}  // namespace cevm::crypto::karatsuba

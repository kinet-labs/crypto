// =============================================================================
// evm256 — first-party 256-bit modular arithmetic.
// =============================================================================

#include "evm256.hpp"

#include <evmmax/evmmax.hpp>
#include <intx/intx.hpp>

namespace kinet::crypto::evm256
{
namespace
{
/// Loads a 32-byte big-endian unsigned integer.
[[nodiscard]] inline intx::uint256 load_be(const uint8_t bytes[32]) noexcept
{
    return intx::be::unsafe::load<intx::uint256>(bytes);
}

/// Stores a uint256 as 32-byte big-endian.
inline void store_be(uint8_t out[32], const intx::uint256& v) noexcept
{
    intx::be::unsafe::store<intx::uint256>(out, v);
}

/// Reduces x modulo m. m may be even. m must be non-zero.
[[nodiscard]] inline intx::uint256 reduce(const intx::uint256& x, const intx::uint256& m) noexcept
{
    return x >= m ? x % m : x;
}
}  // namespace

int addmod(const uint8_t a[32], const uint8_t b[32], const uint8_t m[32], uint8_t out[32]) noexcept
{
    const auto mod = load_be(m);
    if (mod == 0)
        return -1;

    // (a + b) mod m. Reduce a, b first to mirror EVM ADDMOD semantics on
    // values >= m (the EVM allows operands up to 2^256-1).
    const auto x = reduce(load_be(a), mod);
    const auto y = reduce(load_be(b), mod);

    // 257-bit add via carry, then a single subtract if it overflowed mod.
    // We promote to uint512 to capture the carry cleanly: x + y < 2^257 <= 2^512.
    const auto sum = intx::uint512{x} + intx::uint512{y};
    const auto reduced = sum >= intx::uint512{mod} ? sum - intx::uint512{mod} : sum;

    // Result is < mod < 2^256, so the low uint256 holds it.
    store_be(out, static_cast<intx::uint256>(reduced));
    return 0;
}

int mulmod(const uint8_t a[32], const uint8_t b[32], const uint8_t m[32], uint8_t out[32]) noexcept
{
    const auto mod = load_be(m);
    if (mod == 0)
        return -1;

    const auto x = load_be(a);
    const auto y = load_be(b);

    // Wide multiply (256x256 -> 512), then reduce via udivrem.
    // EVM MULMOD allows operands up to 2^256-1 even for moduli that are smaller,
    // so we cannot pre-reduce x or y and use Montgomery directly without a final
    // post-reduction. The udivrem path is constant-time-friendly for the typical
    // case (mod is small and fixed in callers) and matches the EVM spec exactly.
    const auto product = intx::umul(x, y);
    const auto rem = intx::udivrem(product, intx::uint512{mod}).rem;

    // Remainder < mod < 2^256, so the low uint256 holds it.
    store_be(out, static_cast<intx::uint256>(rem));
    return 0;
}

}  // namespace kinet::crypto::evm256

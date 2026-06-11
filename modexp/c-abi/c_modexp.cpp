// =============================================================================
// modexp - C ABI implementation.
//
//   modexp(base, base_len, exp, exp_len, mod, mod_len, out)   EIP-198
//   evm256_addmod(a[32], b[32], m[32], out[32])               EVM ADDMOD
//   evm256_mulmod(a[32], b[32], m[32], out[32])               EVM MULMOD
//
// Wires the public C symbols defined in <kinet_crypto.h> to:
//   * cpp/modexp.cpp           — first-party EIP-198 modexp body.
//   * intx::uint<N> primitives — udivrem / umul for evm256_{add,mul}mod.
//
// EVM ADDMOD/MULMOD semantics: when m == 0 the result is 0. Inputs are
// reduced modulo m before the operation, matching the Yellow Paper.
// =============================================================================

#include "kinet_crypto.h"
#include "../cpp/modexp.hpp"

#include <intx/intx.hpp>

#include <cstring>
#include <span>

namespace
{
inline intx::uint256 be32_to_u256(const uint8_t in[32]) noexcept
{
    return intx::be::unsafe::load<intx::uint256>(in);
}

inline void u256_to_be32(const intx::uint256& v, uint8_t out[32]) noexcept
{
    intx::be::unsafe::store(out, v);
}
}  // namespace

extern "C" int evm256_addmod(const uint8_t a[32], const uint8_t b[32],
                             const uint8_t m[32], uint8_t out[32])
{
    const auto am = be32_to_u256(a);
    const auto bm = be32_to_u256(b);
    const auto mm = be32_to_u256(m);

    if (mm == 0)
    {
        std::memset(out, 0, 32);
        return CRYPTO_OK;
    }

    // Per EVM ADDMOD: result = (a + b) mod m. Reduce inputs modulo m first,
    // then add via 512-bit accumulator and reduce.
    const auto ar = am % mm;
    const auto br = bm % mm;
    const auto sum = intx::uint<512>{ar} + intx::uint<512>{br};
    const auto r = sum % intx::uint<512>{mm};
    u256_to_be32(static_cast<intx::uint256>(r), out);
    return CRYPTO_OK;
}

extern "C" int evm256_mulmod(const uint8_t a[32], const uint8_t b[32],
                             const uint8_t m[32], uint8_t out[32])
{
    const auto am = be32_to_u256(a);
    const auto bm = be32_to_u256(b);
    const auto mm = be32_to_u256(m);

    if (mm == 0)
    {
        std::memset(out, 0, 32);
        return CRYPTO_OK;
    }

    // Per EVM MULMOD: result = (a * b) mod m.
    // intx::umul gives the full 512-bit product without truncation.
    const auto prod = intx::umul(am, bm);
    const auto r = prod % intx::uint<512>{mm};
    u256_to_be32(static_cast<intx::uint256>(r), out);
    return CRYPTO_OK;
}

extern "C" int modexp(const uint8_t* base, size_t base_len,
                      const uint8_t* exp,  size_t exp_len,
                      const uint8_t* mod,  size_t mod_len,
                      uint8_t* out)
{
    if (mod_len == 0)
        return CRYPTO_OK;  // Empty modulus → empty output (nothing to write).

    // EIP-198: modulus of zero produces a zero-filled result of mod_len bytes.
    bool mod_is_zero = true;
    for (size_t i = 0; i < mod_len; ++i)
    {
        if (mod[i] != 0)
        {
            mod_is_zero = false;
            break;
        }
    }
    if (mod_is_zero)
    {
        std::memset(out, 0, mod_len);
        return CRYPTO_OK;
    }

    cevm::crypto::modexp(
        std::span<const uint8_t>{base, base_len},
        std::span<const uint8_t>{exp, exp_len},
        std::span<const uint8_t>{mod, mod_len},
        out);
    return CRYPTO_OK;
}

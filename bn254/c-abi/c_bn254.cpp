// =============================================================================
// bn254 - C ABI implementation (EIP-196 / EIP-197).
//
// Wires the public C symbols defined in <kinet_crypto.h> to the first-party
// C++ body in cpp/bn254.{hpp,cpp} + cpp/pairing/pairing.cpp.
//
//   bn254_add(input[128], output[64])         G1 + G1                EIP-196
//   bn254_mul(input[96],  output[64])         k * G1                 EIP-196
//   bn254_pairing(pairs, n_pairs, output[32]) ∏ e(G1ᵢ,G2ᵢ) == 1      EIP-197
//
// The pairing input ABI per EIP-197: each pair is 192 bytes laid out as
//
//     [G1.x | G1.y | G2.x.imag | G2.x.real | G2.y.imag | G2.y.real]
//      32     32    32          32          32          32
//
// All field elements are 32-byte big-endian integers in [0, p). Out-of-range
// inputs return CRYPTO_ERR_INPUT.
// =============================================================================

#include "kinet_crypto.h"
#include "../cpp/bn254.hpp"
#include "../cpp/ecc.hpp"

#include <cstring>
#include <span>
#include <utility>
#include <vector>

extern "C" int bn254_add(const uint8_t in[128], uint8_t out[64])
{
    using namespace evmmax::bn254;

    const std::span<const uint8_t, 128> input{in, 128};
    const auto p = AffinePoint::from_bytes(input.subspan<0, 64>());
    const auto q = AffinePoint::from_bytes(input.subspan<64, 64>());
    if (!p.has_value() || !q.has_value())
        return CRYPTO_ERR_INPUT;
    if (!validate(*p) || !validate(*q))
        return CRYPTO_ERR_INPUT;

    const auto r = evmmax::ecc::add_affine(*p, *q);
    r.to_bytes(std::span<uint8_t, 64>{out, 64});
    return CRYPTO_OK;
}

extern "C" int bn254_mul(const uint8_t in[96], uint8_t out[64])
{
    using namespace evmmax::bn254;

    const std::span<const uint8_t, 96> input{in, 96};
    const auto p = AffinePoint::from_bytes(input.subspan<0, 64>());
    if (!p.has_value() || !validate(*p))
        return CRYPTO_ERR_INPUT;

    const auto c = intx::be::unsafe::load<intx::uint256>(in + 64);
    const auto r = evmmax::bn254::mul(*p, c);
    r.to_bytes(std::span<uint8_t, 64>{out, 64});
    return CRYPTO_OK;
}

extern "C" int bn254_pairing(const uint8_t* pairs, size_t n_pairs, uint8_t out[32])
{
    using namespace evmmax::bn254;

    std::vector<std::pair<Point, ExtPoint>> v;
    v.reserve(n_pairs);
    for (size_t i = 0; i < n_pairs; ++i)
    {
        const uint8_t* p = pairs + 192 * i;
        // EIP-197: G2 imaginary part comes first in serialization.
        v.emplace_back(
            Point{
                intx::be::unsafe::load<intx::uint256>(p + 0),
                intx::be::unsafe::load<intx::uint256>(p + 32),
            },
            ExtPoint{
                {intx::be::unsafe::load<intx::uint256>(p + 96),
                    intx::be::unsafe::load<intx::uint256>(p + 64)},
                {intx::be::unsafe::load<intx::uint256>(p + 160),
                    intx::be::unsafe::load<intx::uint256>(p + 128)},
            });
    }

    const auto r = pairing_check(v);
    if (!r.has_value())
        return CRYPTO_ERR_INPUT;

    std::memset(out, 0, 32);
    out[31] = *r ? 1 : 0;
    return CRYPTO_OK;
}

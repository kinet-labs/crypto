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

#include "crypto.h"
#include "../cpp/bn254.hpp"
#include "../cpp/ecc.hpp"

#include <cstring>
#include <span>
#include <utility>
#include <vector>

namespace {

inline evmmax::bn254::AffinePoint affine_from_be64(const uint8_t in[64]) noexcept {
    return evmmax::bn254::AffinePoint{
        kinet::crypto::bn254::U256::from_be32(in),
        kinet::crypto::bn254::U256::from_be32(in + 32),
    };
}

inline void affine_to_be64(const evmmax::bn254::AffinePoint& p, uint8_t out[64]) noexcept {
    p.x.to_be32(out);
    p.y.to_be32(out + 32);
}

}  // namespace

extern "C" int bn254_add(const uint8_t in[128], uint8_t out[64])
{
    if (in == nullptr || out == nullptr) return CRYPTO_ERR_INPUT;
    using namespace evmmax::bn254;

    const auto P = affine_from_be64(in);
    const auto Q = affine_from_be64(in + 64);
    if (!validate(P) || !validate(Q)) return CRYPTO_ERR_INPUT;

    // Point addition via mul-by-1 + multi-pair-free affine add: re-use the
    // first-party G1 affine arithmetic directly (g1_add via Jacobian round-trip).
    namespace lc = kinet::crypto::bn254;
    auto to_jac = [](const AffinePoint& a) {
        lc::G1Affine ga;
        if (a.x.is_zero() && a.y.is_zero()) {
            ga.x = lc::U256{}; ga.y = lc::U256{}; ga.infinity = true;
        } else {
            ga.x = lc::to_mont_fp(a.x); ga.y = lc::to_mont_fp(a.y); ga.infinity = false;
        }
        return lc::g1_to_jac(ga);
    };
    const lc::G1Jac sum = lc::g1_add(to_jac(P), to_jac(Q));
    const lc::G1Affine ar = lc::g1_to_affine(sum);
    AffinePoint r{};
    if (ar.infinity) {
        r.x = lc::U256{}; r.y = lc::U256{};
    } else {
        r.x = lc::from_mont_fp(ar.x); r.y = lc::from_mont_fp(ar.y);
    }
    affine_to_be64(r, out);
    return CRYPTO_OK;
}

extern "C" int bn254_mul(const uint8_t in[96], uint8_t out[64])
{
    if (in == nullptr || out == nullptr) return CRYPTO_ERR_INPUT;
    using namespace evmmax::bn254;

    const auto P = affine_from_be64(in);
    if (!validate(P)) return CRYPTO_ERR_INPUT;

    const auto k = kinet::crypto::bn254::U256::from_be32(in + 64);
    const auto r = mul(P, k);
    affine_to_be64(r, out);
    return CRYPTO_OK;
}

extern "C" int bn254_pairing(const uint8_t* pairs, size_t n_pairs, uint8_t out[32])
{
    if (out == nullptr) return CRYPTO_ERR_INPUT;
    if (n_pairs > 0 && pairs == nullptr) return CRYPTO_ERR_INPUT;
    using namespace evmmax::bn254;

    std::vector<std::pair<G1Point, ExtPoint>> v;
    v.reserve(n_pairs);
    for (size_t i = 0; i < n_pairs; ++i) {
        const uint8_t* p = pairs + 192 * i;
        G1Point g1;
        g1.x = kinet::crypto::bn254::U256::from_be32(p + 0);
        g1.y = kinet::crypto::bn254::U256::from_be32(p + 32);
        // EIP-197 G2 layout: x.imag(0..32) || x.real(32..64) || y.imag(64..96) || y.real(96..128)
        // ExtPoint stores .first = real, .second = imag, so swap on read.
        ExtPoint g2;
        g2.x.first  = kinet::crypto::bn254::U256::from_be32(p + 96);   // x.real
        g2.x.second = kinet::crypto::bn254::U256::from_be32(p + 64);   // x.imag
        g2.y.first  = kinet::crypto::bn254::U256::from_be32(p + 160);  // y.real
        g2.y.second = kinet::crypto::bn254::U256::from_be32(p + 128);  // y.imag
        v.emplace_back(std::move(g1), std::move(g2));
    }

    const auto r = pairing_check(v);
    if (!r.has_value()) return CRYPTO_ERR_INPUT;

    std::memset(out, 0, 32);
    out[31] = *r ? 1 : 0;
    return CRYPTO_OK;
}

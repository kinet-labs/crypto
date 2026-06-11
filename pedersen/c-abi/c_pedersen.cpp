// =============================================================================
// pedersen - C ABI implementation.
//
// Two surfaces coexist here:
//
//   1. Legacy single-scalar form (declared in kinet_crypto.h, never wired):
//        pedersen_commit(values, n, blinding[32], commit[33])
//        pedersen_verify(commit[33], values, n, blinding[32])
//      These return CRYPTO_ERR_NOTIMPL until a caller appears.
//
//   2. New vector commitment (this PR):
//        pedersen_generators_from_seed(seed[32], n, out_g_xy, out_h_xy)
//            -> writes 64*n bytes of G_basis (each: x_be32 || y_be32) and
//               64 bytes of H (x_be32 || y_be32). Coordinates emitted in
//               NON-Montgomery form (raw 32-byte big-endian Fp values,
//               identical to gnark-crypto's bn254.G1Affine.X.Bytes()).
//
//        pedersen_vector_commit(scalars[n*32], n, blinding[32],
//                               gens_g_xy[n*64], gens_h_xy[64], out_xy[64])
//            -> writes 64 bytes of commitment (x_be32 || y_be32).
//
//        pedersen_vector_verify_open(commitment_xy[64], scalars[n*32], n,
//                                    blinding[32], gens_g_xy[n*64],
//                                    gens_h_xy[64])
//            -> returns CRYPTO_OK iff Commit matches commitment,
//               CRYPTO_ERR_INPUT otherwise.
//
// All inputs and outputs are 32-byte big-endian (raw Fp / Fr); the C++ core
// in pedersen/cpp/ keeps point coordinates in Montgomery form internally.
// =============================================================================

#include "kinet_crypto.h"
#include "../cpp/pedersen.hpp"
#include "../../bn254/cpp/bn254_fp.hpp"
#include "../../bn254/cpp/bn254_g1.hpp"

#include <cstdint>
#include <cstring>
#include <vector>

namespace lc = kinet::crypto::bn254;
namespace lp = kinet::crypto::pedersen;

// -------------------------- Legacy single-scalar form -----------------------

extern "C" int pedersen_commit(const uint8_t*, size_t,
                               const uint8_t[32], uint8_t[33]) {
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int pedersen_verify(const uint8_t[33], const uint8_t*,
                               size_t, const uint8_t[32]) {
    return CRYPTO_ERR_NOTIMPL;
}

// ----------------------------- Vector commitment ---------------------------

namespace {

bool fp_be32_to_mont(const uint8_t in[32], lc::U256& out) noexcept {
    const lc::U256 raw = lc::U256::from_be32(in);
    if (lc::U256::cmp(raw, lc::P) >= 0) return false;
    out = lc::to_mont_fp(raw);
    return true;
}

void fp_mont_to_be32(const lc::U256& v, uint8_t out[32]) noexcept {
    const lc::U256 raw = lc::from_mont_fp(v);
    raw.to_be32(out);
}

void fr_be32_to_u256_reduced(const uint8_t in[32], lc::U256& out) noexcept {
    lc::U256 raw = lc::U256::from_be32(in);
    while (lc::U256::cmp(raw, lc::FR_ORDER) >= 0) {
        uint64_t bw;
        raw = lc::sub_256(raw, lc::FR_ORDER, bw);
    }
    // g1_scalar_mul consumes the scalar as a plain 256-bit integer (bit
    // ladder); no Montgomery conversion is needed.
    out = raw;
}

bool decode_g1_one(const uint8_t xy[64], lc::G1Affine& p) noexcept {
    if (!fp_be32_to_mont(xy + 0,  p.x)) return false;
    if (!fp_be32_to_mont(xy + 32, p.y)) return false;
    if (p.x.is_zero() && p.y.is_zero()) {
        p.x = lc::U256{}; p.y = lc::U256{}; p.infinity = true;
    } else {
        p.infinity = false;
        if (!lc::g1_is_on_curve(p)) return false;
    }
    return true;
}

bool decode_g1_basis(const uint8_t* xy, std::size_t n,
                     std::vector<lc::G1Affine>& out) noexcept {
    out.clear();
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        lc::G1Affine p;
        if (!decode_g1_one(xy + 64 * i, p)) return false;
        out.push_back(p);
    }
    return true;
}

void encode_g1_one(const lc::G1Affine& p, uint8_t out[64]) noexcept {
    if (p.infinity) {
        std::memset(out, 0, 64);
        return;
    }
    fp_mont_to_be32(p.x, out + 0);
    fp_mont_to_be32(p.y, out + 32);
}

}  // namespace

extern "C" int pedersen_generators_from_seed(const uint8_t seed[32],
                                             size_t n,
                                             uint8_t* out_g_xy,
                                             uint8_t out_h_xy[64]) {
    if (seed == nullptr || n == 0) return CRYPTO_ERR_INPUT;
    if (out_g_xy == nullptr || out_h_xy == nullptr) return CRYPTO_ERR_INPUT;

    lp::Generators gens;
    if (!lp::Generators::from_seed(seed, n, gens)) return CRYPTO_ERR_INPUT;

    for (std::size_t i = 0; i < n; ++i) {
        encode_g1_one(gens.G_basis[i], out_g_xy + 64 * i);
    }
    encode_g1_one(gens.H, out_h_xy);
    return CRYPTO_OK;
}

extern "C" int pedersen_vector_commit(const uint8_t* scalars, size_t n,
                                      const uint8_t blinding[32],
                                      const uint8_t* gens_g_xy,
                                      const uint8_t gens_h_xy[64],
                                      uint8_t out_xy[64]) {
    if (n == 0) return CRYPTO_ERR_INPUT;
    if (scalars == nullptr || blinding == nullptr) return CRYPTO_ERR_INPUT;
    if (gens_g_xy == nullptr || gens_h_xy == nullptr || out_xy == nullptr)
        return CRYPTO_ERR_INPUT;

    lp::Generators gens;
    if (!decode_g1_basis(gens_g_xy, n, gens.G_basis)) return CRYPTO_ERR_INPUT;
    if (!decode_g1_one(gens_h_xy, gens.H)) return CRYPTO_ERR_INPUT;

    std::vector<lc::U256> sc(n);
    for (std::size_t i = 0; i < n; ++i) {
        fr_be32_to_u256_reduced(scalars + 32 * i, sc[i]);
    }
    lc::U256 r;
    fr_be32_to_u256_reduced(blinding, r);

    const lc::G1Affine c = lp::commit(
        std::span<const lc::U256>{sc.data(), sc.size()}, r, gens);
    encode_g1_one(c, out_xy);
    return CRYPTO_OK;
}

extern "C" int pedersen_vector_verify_open(const uint8_t commitment_xy[64],
                                           const uint8_t* scalars, size_t n,
                                           const uint8_t blinding[32],
                                           const uint8_t* gens_g_xy,
                                           const uint8_t gens_h_xy[64]) {
    if (n == 0) return CRYPTO_ERR_INPUT;
    if (commitment_xy == nullptr || scalars == nullptr || blinding == nullptr)
        return CRYPTO_ERR_INPUT;
    if (gens_g_xy == nullptr || gens_h_xy == nullptr) return CRYPTO_ERR_INPUT;

    lp::Generators gens;
    if (!decode_g1_basis(gens_g_xy, n, gens.G_basis)) return CRYPTO_ERR_INPUT;
    if (!decode_g1_one(gens_h_xy, gens.H)) return CRYPTO_ERR_INPUT;

    lc::G1Affine c;
    if (!decode_g1_one(commitment_xy, c)) return CRYPTO_ERR_INPUT;

    std::vector<lc::U256> sc(n);
    for (std::size_t i = 0; i < n; ++i) {
        fr_be32_to_u256_reduced(scalars + 32 * i, sc[i]);
    }
    lc::U256 r;
    fr_be32_to_u256_reduced(blinding, r);

    const bool ok = lp::verify_open(
        c, std::span<const lc::U256>{sc.data(), sc.size()}, r, gens);
    return ok ? CRYPTO_OK : CRYPTO_ERR_INPUT;
}

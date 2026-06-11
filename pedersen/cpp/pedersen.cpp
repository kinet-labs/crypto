// First-party Pedersen vector commitment over BN254 G1 -- implementation.

#include "pedersen.hpp"
#include "bn254_hash_to_curve.hpp"

namespace kinet::crypto::pedersen {

namespace {

namespace lc = kinet::crypto::bn254;

// Encode (seed || u64_le(index)) into a 40-byte message buffer for
// HashToG1. Replicate exactly in any Go/Rust reference: little-endian u64.
inline void build_index_msg(const uint8_t seed[32], uint64_t index,
                            uint8_t out[40]) noexcept {
    for (int i = 0; i < 32; ++i) out[i] = seed[i];
    for (int i = 0; i < 8; ++i) {
        out[32 + i] = (uint8_t)((index >> (8 * i)) & 0xFFu);
    }
}

}  // namespace

bool Generators::from_seed(const uint8_t seed[32], std::size_t n,
                           Generators& out) noexcept {
    if (n == 0) return false;
    if (seed == nullptr) return false;

    out.G_basis.clear();
    out.G_basis.reserve(n);

    std::span<const uint8_t> dst{
        reinterpret_cast<const uint8_t*>(DST_SEEDED_GEN), DST_SEEDED_GEN_LEN};

    uint8_t msg[40];
    for (uint64_t i = 0; i < (uint64_t)n; ++i) {
        build_index_msg(seed, i, msg);
        lc::G1Affine p = lc::h2c::hash_to_curve_g1(
            std::span<const uint8_t>{msg, sizeof(msg)}, dst);
        out.G_basis.push_back(p);
    }
    build_index_msg(seed, (uint64_t)n, msg);
    out.H = lc::h2c::hash_to_curve_g1(
        std::span<const uint8_t>{msg, sizeof(msg)}, dst);

    return true;
}

lc::G1Affine commit(std::span<const lc::U256> scalars,
                    const lc::U256& blinding,
                    const Generators& gens) noexcept {
    if (scalars.size() != gens.G_basis.size()) {
        // Length mismatch -> point at infinity (caller-recoverable sentinel;
        // the C-ABI shim returns CRYPTO_ERR_INPUT before reaching here).
        lc::G1Affine inf;
        inf.x = lc::U256{}; inf.y = lc::U256{}; inf.infinity = true;
        return inf;
    }

    lc::G1Jac acc = lc::g1_jac_zero();

    // sum_i scalars[i] * G_basis[i]
    for (std::size_t i = 0; i < scalars.size(); ++i) {
        const lc::G1Jac term = lc::g1_scalar_mul(gens.G_basis[i], scalars[i]);
        acc = lc::g1_add(acc, term);
    }

    // + blinding * H
    {
        const lc::G1Jac term = lc::g1_scalar_mul(gens.H, blinding);
        acc = lc::g1_add(acc, term);
    }

    return lc::g1_to_affine(acc);
}

bool verify_open(const lc::G1Affine& commitment,
                 std::span<const lc::U256> scalars,
                 const lc::U256& blinding,
                 const Generators& gens) noexcept {
    const lc::G1Affine recomputed = commit(scalars, blinding, gens);

    if (recomputed.infinity != commitment.infinity) return false;
    if (commitment.infinity) return true;
    return recomputed.x == commitment.x && recomputed.y == commitment.y;
}

}  // namespace kinet::crypto::pedersen

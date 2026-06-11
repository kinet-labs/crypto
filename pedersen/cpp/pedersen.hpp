// First-party Pedersen vector commitment over BN254 G1.
//
// Scheme:
//
//   Commit(s_0, ..., s_{n-1}; r) = sum_i s_i * G_i  +  r * H
//
// where (G_0, ..., G_{n-1}, H) are independently sampled BN254 G1 generators.
//
// Reproducibility:
//
//   Generators are derived deterministically from a 32-byte seed via RFC 9380
//   hash-to-curve (BN254G1_XMD:SHA-256_SVDW_RO_) over BN254 G1 with domain
//   separation tag DST = "PEDERSEN_SEEDED_GEN_V1":
//
//     G_i = HashToG1( seed || u64_le(i),       DST )   for i in 0..n-1
//     H   = HashToG1( seed || u64_le(n),       DST )
//
//   This is byte-for-byte compatible with the Go canonical at
//   github.com/kinet-labs/crypto/pedersen/pedersen_seed.go (single-scalar case
//   n = 1) and with the Go reference fixture generator at
//   pedersen/test/tools/gen_pedersen_kat.go (vector case, arbitrary n).
//
// Constant-time: scalar multiplication uses the bn254 G1 Montgomery ladder
// (no GLV, no windowed wNAF). Side-channel risk is the same as a single
// secp256k1 / bn254 scalar mul.
//
// Self-contained: the only dependency is the bn254 cpu archive (Fp/Fr/G1
// arithmetic plus hash-to-curve). No external libraries.

#pragma once

#include "bn254_fp.hpp"
#include "bn254_g1.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace kinet::crypto::pedersen {

// Domain separation tag for seed-derived generators. Brand-neutral; do not
// add a "KINET_" prefix. Replicate exactly in any cross-language port.
constexpr const char DST_SEEDED_GEN[] = "PEDERSEN_SEEDED_GEN_V1";
constexpr std::size_t DST_SEEDED_GEN_LEN = sizeof(DST_SEEDED_GEN) - 1;  // strip NUL

// Generators is the set of independent G1 points used by a Pedersen vector
// commitment instance. Reuse the same Generators across commitments for
// homomorphism to be meaningful.
//
// Coordinates are stored in Montgomery form (the layout used by
// bn254::g1_scalar_mul / g1_add).
struct Generators {
    std::vector<kinet::crypto::bn254::G1Affine> G_basis;
    kinet::crypto::bn254::G1Affine H;

    // Deterministically derive (G_0, ..., G_{n-1}, H) from a 32-byte seed
    // via RFC 9380 hash-to-curve. n must be >= 1.
    //
    // Returns false if n == 0 or seed is null. Otherwise returns true and
    // populates `out`. BN254 G1 has cofactor 1, so HashToG1 is total.
    static bool from_seed(const uint8_t seed[32], std::size_t n,
                          Generators& out) noexcept;
};

// Commit returns sum_i scalars[i] * G_basis[i] + blinding * H as an affine
// G1 point in Montgomery form. scalars.size() must equal gens.G_basis.size().
//
// Inputs:
//   scalars  - sequence of Fr scalars as raw 256-bit integers (each must be
//              already reduced modulo r). The bn254 Montgomery ladder
//              consumes the scalar bit-by-bit so no Mont conversion is
//              applied here.
//   blinding - blinding factor as a raw 256-bit integer (already reduced).
//   gens     - generators previously produced by from_seed (or any other
//              source).
//
// Returns: G1Affine with x, y in Montgomery form.
kinet::crypto::bn254::G1Affine commit(
    std::span<const kinet::crypto::bn254::U256> scalars,
    const kinet::crypto::bn254::U256& blinding,
    const Generators& gens) noexcept;

// verify_open returns true iff Commit(scalars, blinding, gens) == commitment.
// commitment is compared to the recomputed Commit by infinity flag and by
// Montgomery-form (x, y) equality.
bool verify_open(const kinet::crypto::bn254::G1Affine& commitment,
                 std::span<const kinet::crypto::bn254::U256> scalars,
                 const kinet::crypto::bn254::U256& blinding,
                 const Generators& gens) noexcept;

}  // namespace kinet::crypto::pedersen

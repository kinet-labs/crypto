// First-party RFC 9380 hash-to-curve for bn254 G1 -- public surface.
//
// Suite: BN254G1_XMD:SHA-256_SVDW_RO_  (RFC 9380 §8.5)
//   * expand_message_xmd with SHA-256 (RFC 9380 §5.4.1)
//   * hash_to_field (RFC 9380 §5.3) with L = 48, count = 2
//   * map_to_curve via Shallue / van de Woestijne (RFC 9380 §6.6.1) -- the
//     universal map; required because BN254 G1 has A = 0 so the simplified
//     SWU (§6.6.2) does not apply directly. The §6.6.4 "AB == 0" rationale
//     is realised via SVDW for j-invariant-0 curves.
//   * BN254 G1 has cofactor 1, so clear_cofactor is the identity map.
//
// The map matches gnark-crypto v0.20.1 ecc/bn254/hash_to_g1.go::HashToG1
// byte-for-byte (verified by KAT in bn254/test/bn254_kat_test.cpp).
//
// SHA-256 is embedded in bn254_hash_to_curve.cpp to keep the bn254 module
// link-orthogonal -- no cross-module dependency on kinet::sha256_cpu just for
// hash-to-curve.
//
// Constant-time: not required. The input (msg, dst) is public.

#pragma once

#include "bn254_fp.hpp"
#include "bn254_g1.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace kinet::crypto::bn254::h2c {

// expand_message_xmd with SHA-256 (RFC 9380 §5.4.1). Returns len_in_bytes
// pseudorandom bytes given (msg, dst). Returns an empty vector on misuse
// (dst.size() > 255 or len_in_bytes pushes ell over 255).
std::vector<uint8_t> expand_message_xmd_sha256(
    std::span<const uint8_t> msg,
    std::span<const uint8_t> dst,
    std::size_t len_in_bytes);

// hash_to_field for BN254 Fp with L = 48, count = 2 (RFC 9380 §5.3).
// Output elements are in Montgomery form.
std::array<U256, 2> hash_to_field_2(
    std::span<const uint8_t> msg,
    std::span<const uint8_t> dst);

// SVDW map_to_curve (RFC 9380 §6.6.1). u_mont is in Montgomery form;
// the returned affine point's coordinates are also in Montgomery form.
G1Affine map_to_curve_svdw(const U256& u_mont);

// Full random-oracle hash-to-curve (RFC 9380 §3). Cofactor of BN254 G1
// is 1, so no cofactor clearing is performed.
// Returned affine point is in Montgomery form.
G1Affine hash_to_curve_g1(
    std::span<const uint8_t> msg,
    std::span<const uint8_t> dst);

}  // namespace kinet::crypto::bn254::h2c

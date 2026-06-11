// First-party bn254 (alt_bn128) implementation. Public API matches the
// surface that the c-abi shim wires against:
//
//   evmmax::bn254::validate(pt)         - membership test
//   evmmax::bn254::mul(pt, c)           - G1 scalar multiplication
//   evmmax::bn254::pairing_check(pairs) - EIP-197 pairing predicate
//   evmmax::bn254::hash_to_g1(msg, dst) - RFC 9380 SSWU map-to-curve
//
// The legacy cevm-vendored body has been removed in favour of this
// first-party implementation. See bn254_fp.hpp (field) and bn254_g1.hpp
// (curve). The `evmmax::bn254` namespace and the validate/mul/pairing_check
// signatures are preserved for migration safety: the c-abi shim and any
// existing callers continue to link unchanged.

#pragma once

#include "bn254_fp.hpp"
#include "bn254_fp2.hpp"
#include "bn254_g1.hpp"
#include "bn254_g2.hpp"
#include "bn254_pairing.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace evmmax::bn254 {

using uint256 = kinet::crypto::bn254::U256;

struct AffinePoint {
    uint256 x;
    uint256 y;

    bool operator==(const AffinePoint&) const noexcept = default;
    bool operator==(int v) const noexcept {
        return v == 0 && x.is_zero() && y.is_zero();
    }
};

template <typename T>
struct Point {
    T x;
    T y;
};

using G1Point  = Point<uint256>;
using ExtPoint = Point<std::pair<uint256, uint256>>;

bool validate(const AffinePoint& pt) noexcept;

AffinePoint mul(const AffinePoint& pt, const uint256& c) noexcept;

std::optional<bool> pairing_check(
    std::span<const std::pair<G1Point, ExtPoint>> pairs) noexcept;

bool hash_to_g1(std::span<const uint8_t> msg, std::span<const uint8_t> dst,
                AffinePoint& out) noexcept;

}  // namespace evmmax::bn254

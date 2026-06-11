// =============================================================================
// evm256 — 256-bit modular arithmetic over arbitrary modulus.
//
// Inputs and outputs are 32-byte big-endian unsigned integers.
// modulus must be non-zero. modulus == 1 yields output 0 for every operation.
//
// First-party CPU body. Built on intx::uint256 (vendored at deps/intx) and
// evmmax::ModArith<intx::uint256> (vendored at deps/evmmax). No blst, no
// external runtime libraries.
//
// Reference: github.com/ethereum/evmone (lib/evmmax/evmmax.hpp), Apache-2.0,
// vendored verbatim at kinet-labs/crypto/deps/evmmax/include/evmmax/evmmax.hpp.
//
// Operations:
//   addmod(a, b, m) -> (a + b) mod m
//   mulmod(a, b, m) -> (a * b) mod m
//
// =============================================================================

#pragma once

#include <cstdint>

namespace kinet::crypto::evm256
{
/// Computes (a + b) mod m. Inputs and output are 32-byte big-endian.
/// Returns 0 on success, -1 if m is zero.
int addmod(const uint8_t a[32], const uint8_t b[32], const uint8_t m[32], uint8_t out[32]) noexcept;

/// Computes (a * b) mod m. Inputs and output are 32-byte big-endian.
/// Returns 0 on success, -1 if m is zero.
int mulmod(const uint8_t a[32], const uint8_t b[32], const uint8_t m[32], uint8_t out[32]) noexcept;

}  // namespace kinet::crypto::evm256

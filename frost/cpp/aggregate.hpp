// FROST aggregate — combines per-signer commitments and partial signatures
// into a final BIP-340-style 64-byte Schnorr signature on secp256k1.
//
// RFC 9591 §5.2 (FROST(secp256k1, SHA-256)) round-2 aggregation, encoded
// for the BIP-340 wire format used by the public C-ABI:
//
//   sig[64] = R_x[32] || z[32]
//
// where:
//   R = sum_i (D_i + rho_i * E_i)              -- aggregate nonce point
//   z = sum_i z_i  (mod n)                     -- aggregate response
//   R_x = x-only encoding of R, with R adjusted to even-y if needed
//        (BIP-340 even-y convention; the verifier will lift_x with even-y
//        and the same convention used at sign time keeps the equation valid)
//
// Aggregation runs over public values only. No constant-time requirement.
//
// Per-signer input layout (`partial_t::FROST_PARTIAL_LEN` = 130 bytes):
//
//   D_i  [33]  // compressed sec1 point  (signer's first nonce commitment)
//   E_i  [33]  // compressed sec1 point  (signer's second nonce commitment)
//   z_i  [32]  // big-endian scalar      (signer's partial response)
//   rho_i[32]  // big-endian scalar      (signer's binding factor for this msg)
//
// The binding factor rho_i is the per-signer scalar derived in round 2
// from (i, msg, B). It is supplied by the caller — derivation is part of
// the protocol layer above this primitive.

#pragma once

#include <cstddef>
#include <cstdint>

namespace kinet::crypto::frost {

constexpr std::size_t FROST_PARTIAL_LEN = 33 + 33 + 32 + 32;  // = 130

// Aggregate n_partials signer contributions into a 64-byte BIP-340 signature.
//
// partials       : n_partials * FROST_PARTIAL_LEN bytes, packed signer-major
// n_partials     : number of signers contributing
// sig_out        : 64 bytes = R_x[32] || z[32]
//
// Returns 0 on success, -1 on null/zero input, -2 if any commitment fails to
// decode, -3 if the aggregate point is the identity (degenerate, impossible
// in honest runs).
int aggregate(const uint8_t* partials,
              std::size_t    n_partials,
              uint8_t        sig_out[64]) noexcept;

}  // namespace kinet::crypto::frost

// First-party secp256k1 ECDSA sign / verify / sk_to_pk.
//
// Built on top of the existing field, curve, and windowed-G-table primitives:
//   field.hpp           - Fp/Fr Montgomery (P, N, fp_*, fn_*)
//   curve.hpp           - JacobianPoint, jac_double, jac_add, jac_mul
//   windowed_g_table.hpp - precomputed G-table for fast sk*G
//
// Determinism: signing uses RFC 6979 deterministic-k (HMAC-SHA256 of
// (sk||z)). The same input produces the same (r, s) every call, which lets
// the determinism harness compare against KAT vectors.
//
// Public API:
//   secret_to_public(sk, pk)       sk -> 64-byte uncompressed pk
//   sign(sk, msg32, sig, recid)    deterministic ECDSA, BIP-62 Low-S
//   verify(pk, msg32, sig)         standard ECDSA verify

#pragma once

#include <cstdint>

namespace kinet::crypto::secp256k1 {

// Status codes returned by the sign/verify entry points.
enum class EcdsaStatus : int {
    OK = 0,
    InvalidSecret = -1,    // sk == 0 or sk >= n
    InvalidPubkey = -2,    // pk not on curve / at infinity
    InvalidSignature = -3, // r or s out of range
    VerifyFailed = -4,     // signature does not verify
};

// Compute pk = sk * G in uncompressed (X || Y) form, 64 bytes big-endian.
// Returns InvalidSecret if sk == 0 or sk >= n.
EcdsaStatus secret_to_public(const uint8_t sk[32], uint8_t pk[64]) noexcept;

// Deterministic ECDSA sign per RFC 6979 + BIP-62 Low-S.
// `sig` receives r||s big-endian (64 bytes); `recid` receives 0..3 recovery id.
EcdsaStatus sign(const uint8_t sk[32], const uint8_t msg32[32],
                 uint8_t sig[64], uint8_t* recid) noexcept;

// Verify an ECDSA signature against an uncompressed pubkey.
EcdsaStatus verify(const uint8_t pk[64], const uint8_t msg32[32],
                   const uint8_t sig[64]) noexcept;

}  // namespace kinet::crypto::secp256k1

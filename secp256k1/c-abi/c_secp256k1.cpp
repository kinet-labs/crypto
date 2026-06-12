// =============================================================================
// secp256k1 - C ABI for the umbrella header
// =============================================================================
// The first-party body in cpp/ecrecover.cpp exports the canonical entry point
// secp256k1_ecrecover(hash, r, s, v, pubkey). This file maps the unified
// surface (secp256k1_recover, secp256k1_*) onto that body.
// =============================================================================

#include "crypto.h"
#include "kinet/crypto/secp256k1.h"
#include "../cpp/ecdsa.hpp"

#include <cstring>

extern "C" int secp256k1_recover(const uint8_t msg32[32],
                                 const uint8_t sig[65],
                                 uint8_t pubkey[64]) {
    if (!msg32 || !sig || !pubkey) return CRYPTO_ERR_INPUT;

    // sig is r(32) || s(32) || v(1).
    const uint8_t* r = sig;
    const uint8_t* s = sig + 32;
    uint8_t v        = sig[64];

    secp256k1_status st = secp256k1_ecrecover(msg32, r, s, v, pubkey);
    return st == SECP256K1_OK ? CRYPTO_OK : CRYPTO_ERR_VERIFY;
}

// First-party ECDSA sign / verify / sk_to_pk wired to cpp/ecdsa.{hpp,cpp}.
// RFC 6979 deterministic-k for sign; BIP-62 Low-S enforced; verify validates
// pubkey on-curve before scalar arithmetic.
extern "C" int secp256k1_sign(const uint8_t sk[32],
                              const uint8_t msg32[32],
                              uint8_t sig[64],
                              uint8_t* recid) {
    if (sk == nullptr || msg32 == nullptr || sig == nullptr || recid == nullptr)
        return CRYPTO_ERR_INPUT;
    using kinet::crypto::secp256k1::EcdsaStatus;
    const auto st = kinet::crypto::secp256k1::sign(sk, msg32, sig, recid);
    switch (st) {
        case EcdsaStatus::OK:                return CRYPTO_OK;
        case EcdsaStatus::InvalidSecret:     return CRYPTO_ERR_INPUT;
        case EcdsaStatus::InvalidSignature:  return CRYPTO_ERR_INTERNAL;
        default:                             return CRYPTO_ERR_INTERNAL;
    }
}

extern "C" int secp256k1_verify(const uint8_t pk[64],
                                const uint8_t msg32[32],
                                const uint8_t sig[64]) {
    if (pk == nullptr || msg32 == nullptr || sig == nullptr)
        return CRYPTO_ERR_INPUT;
    using kinet::crypto::secp256k1::EcdsaStatus;
    const auto st = kinet::crypto::secp256k1::verify(pk, msg32, sig);
    switch (st) {
        case EcdsaStatus::OK:                return CRYPTO_OK;
        case EcdsaStatus::InvalidPubkey:     return CRYPTO_ERR_INPUT;
        case EcdsaStatus::InvalidSignature:  return CRYPTO_ERR_INPUT;
        case EcdsaStatus::VerifyFailed:      return CRYPTO_ERR_VERIFY;
        default:                             return CRYPTO_ERR_INTERNAL;
    }
}

extern "C" int secp256k1_sk_to_pk(const uint8_t sk[32], uint8_t pk[64]) {
    if (sk == nullptr || pk == nullptr) return CRYPTO_ERR_INPUT;
    using kinet::crypto::secp256k1::EcdsaStatus;
    const auto st = kinet::crypto::secp256k1::secret_to_public(sk, pk);
    return st == EcdsaStatus::OK ? CRYPTO_OK : CRYPTO_ERR_INPUT;
}

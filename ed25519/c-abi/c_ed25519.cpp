// =============================================================================
// ed25519 - C ABI implementation
// =============================================================================
//
// Forwards the public C ABI (declared in c-abi/kinet_crypto.h) to the
// kinet::crypto::ed25519 host CPU implementation. The C-ABI uses RFC 8032 sk
// (32-byte seed); the C++ wrapper uses the NaCl 64-byte sk (seed || pk) so
// sign() can avoid recomputing pk. We bridge by deriving pk from the seed
// once per sign call.
// =============================================================================

#include "kinet_crypto.h"
#include "../cpp/ed25519.hpp"

#include <cstdint>
#include <cstddef>

extern "C" int ed25519_keygen(const uint8_t seed[32],
                               uint8_t       sk[32],
                               uint8_t       pk[32]) {
    if (!seed || !sk || !pk) return CRYPTO_ERR_INPUT;
    uint8_t expanded_sk[64];
    kinet::crypto::ed25519::keygen(pk, expanded_sk, seed);
    // The 32-byte sk in the C ABI is the RFC 8032 seed (canonical form).
    for (int i = 0; i < 32; ++i) sk[i] = expanded_sk[i];
    return CRYPTO_OK;
}

extern "C" int ed25519_sign(const uint8_t  sk[32],
                             const uint8_t* msg, size_t msg_len,
                             uint8_t        sig[64]) {
    if (!sk || !sig) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && !msg) return CRYPTO_ERR_INPUT;
    // sk is the seed; derive (pk, expanded_sk) then sign.
    uint8_t pk[32];
    uint8_t expanded_sk[64];
    kinet::crypto::ed25519::keygen(pk, expanded_sk, sk);
    kinet::crypto::ed25519::sign(sig, msg, msg_len, pk, expanded_sk);
    return CRYPTO_OK;
}

extern "C" int ed25519_verify(const uint8_t  pk[32],
                               const uint8_t* msg, size_t msg_len,
                               const uint8_t  sig[64]) {
    if (!pk || !sig) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && !msg) return CRYPTO_ERR_INPUT;
    return kinet::crypto::ed25519::verify(msg, msg_len, sig, pk)
               ? CRYPTO_OK
               : CRYPTO_ERR_VERIFY;
}

// =============================================================================
// kinet-labs/crypto/sr25519 — C-ABI shim
// =============================================================================
// Wraps kinet-labs/sr25519-crust (pure-C donna) behind the brand-neutral C-ABI
// declared in <crypto.h>:
//
//   int sr25519_sign  (const uint8_t sk[32], const uint8_t* msg, size_t len, uint8_t sig[64]);
//   int sr25519_verify(const uint8_t pk[32], const uint8_t* msg, size_t len, const uint8_t sig[64]);
//
// donna keypair layout: [secret(32) | nonce(32) | public(32)] = 96 B. The
// C-ABI takes a 32-byte SEED (Substrate `MiniSecretKey` convention); the
// bridge helpers in donna_bridge.c expand to the donna keypair on each call.
// This preserves the v1.x C-ABI signature.
//
// donna_bridge.c is a separate TU because the donna public header declares
// `sr25519_sign` / `sr25519_verify` with different signatures from the
// kinet-labs C-ABI of the same name; they cannot share a TU.
// =============================================================================

#include "crypto.h"
#include "donna_bridge.h"

extern "C" int sr25519_sign(const uint8_t sk[32], const uint8_t* msg, size_t msg_len,
                            uint8_t sig[64]) {
    if (sk == nullptr || sig == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;

    kinet-labs_sr25519_sign_from_seed(sig, sk, msg, msg_len);
    return CRYPTO_OK;
}

extern "C" int sr25519_verify(const uint8_t pk[32], const uint8_t* msg, size_t msg_len,
                              const uint8_t sig[64]) {
    if (pk == nullptr || sig == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;

    return kinet-labs_sr25519_verify_seed(sig, msg, msg_len, pk) ? CRYPTO_OK
                                                             : CRYPTO_ERR_VERIFY;
}

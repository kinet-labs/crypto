#include "crypto.h"

extern "C" int sr25519_sign(const uint8_t sk[32], const uint8_t* msg, size_t msg_len,
                            uint8_t sig[64]) {
    if (sk == nullptr || sig == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int sr25519_verify(const uint8_t pk[32], const uint8_t* msg, size_t msg_len,
                              const uint8_t sig[64]) {
    if (pk == nullptr || sig == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    return CRYPTO_ERR_NOTIMPL;
}

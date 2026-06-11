#include "crypto.h"

struct ringtail_ctx {};

extern "C" int ringtail_setup(uint32_t /*t*/, uint32_t /*n*/, ringtail_ctx** out) {
    if (out == nullptr) return CRYPTO_ERR_INPUT;
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int ringtail_sign(ringtail_ctx* ctx,
                             const uint8_t* msg, size_t msg_len,
                             uint8_t* sig, size_t* sig_len) {
    if (ctx == nullptr || sig == nullptr || sig_len == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int ringtail_verify(const uint8_t* pk, size_t pk_len,
                               const uint8_t* msg, size_t msg_len,
                               const uint8_t* sig, size_t sig_len) {
    if (pk_len  > 0 && pk  == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    if (sig_len > 0 && sig == nullptr) return CRYPTO_ERR_INPUT;
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" void ringtail_destroy(ringtail_ctx* /*ctx*/) {}

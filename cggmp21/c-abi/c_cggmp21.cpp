#include "crypto.h"

struct cggmp21_ctx {};

extern "C" int cggmp21_setup(uint32_t /*t*/, uint32_t /*n*/, cggmp21_ctx** out) {
    if (out == nullptr) return CRYPTO_ERR_INPUT;
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int cggmp21_partial_sign(cggmp21_ctx* ctx,
                                    const uint8_t* msg, size_t msg_len,
                                    uint32_t /*signer_id*/, uint8_t* partial) {
    if (ctx == nullptr || partial == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int cggmp21_aggregate(cggmp21_ctx* ctx,
                                 const uint8_t* partials, size_t n,
                                 uint8_t sig[64]) {
    if (ctx == nullptr || sig == nullptr) return CRYPTO_ERR_INPUT;
    if (n > 0 && partials == nullptr) return CRYPTO_ERR_INPUT;
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int cggmp21_verify(const uint8_t pk[64],
                              const uint8_t* msg, size_t msg_len,
                              const uint8_t sig[64]) {
    if (pk == nullptr || sig == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" void cggmp21_destroy(cggmp21_ctx* /*ctx*/) {}

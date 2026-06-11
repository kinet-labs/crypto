#include "crypto.h"

struct frost_ctx {};

extern "C" int frost_setup(uint32_t /*t*/, uint32_t /*n*/, frost_ctx** out) {
    if (out == nullptr) return CRYPTO_ERR_INPUT;
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int frost_partial_sign(frost_ctx* ctx,
                                  const uint8_t* msg, size_t msg_len,
                                  uint32_t /*signer_id*/, uint8_t* partial) {
    if (ctx == nullptr || partial == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int frost_aggregate(frost_ctx* ctx,
                               const uint8_t* partials, size_t n_partials,
                               uint8_t sig[64]) {
    if (ctx == nullptr || sig == nullptr) return CRYPTO_ERR_INPUT;
    if (n_partials > 0 && partials == nullptr) return CRYPTO_ERR_INPUT;
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int frost_verify(const uint8_t pk[32],
                            const uint8_t* msg, size_t msg_len,
                            const uint8_t sig[64]) {
    if (pk == nullptr || sig == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" void frost_destroy(frost_ctx* /*ctx*/) {}

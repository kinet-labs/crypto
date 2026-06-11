// =============================================================================
// secp256r1 - C ABI implementation (Phase 1 stub)
// =============================================================================

#include "crypto.h"

extern "C" int secp256r1_verify(const uint8_t pk[64],
                                const uint8_t* msg, size_t msg_len,
                                const uint8_t sig[64]) {
    if (pk == nullptr || sig == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    return CRYPTO_ERR_NOTIMPL;
}

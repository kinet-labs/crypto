// =============================================================================
// secp256r1 - C ABI implementation (Phase 1 stub)
// =============================================================================

#include "kinet_crypto.h"

extern "C" int secp256r1_verify(const uint8_t /*pk*/[64],
                                const uint8_t* /*msg*/, size_t /*msg_len*/,
                                const uint8_t /*sig*/[64]) {
    return CRYPTO_ERR_NOTIMPL;
}

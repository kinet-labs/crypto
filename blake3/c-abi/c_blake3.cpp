// =============================================================================
// blake3 - C ABI (Phase 1 stub).
// CPU body lives in legacy kinet-labs/crypto/src/crypto.cpp (crypto_blake3); a
// first-class CPU implementation lands in Phase 3.
// =============================================================================

#include "kinet_crypto.h"

extern "C" int kinet_blake3(const uint8_t* /*in*/, size_t /*in_len*/, uint8_t /*out*/[32]) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_blake3_batch(const uint8_t* const* /*in*/, const size_t* /*in_len*/,
                                size_t /*n*/, uint8_t* /*out*/) {
    return KINET_ERR_NOTIMPL;
}

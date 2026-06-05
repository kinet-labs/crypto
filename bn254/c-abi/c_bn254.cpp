// =============================================================================
// bn254 - C ABI implementation (Phase 1 stub)
// CPU body in cpp/bn254.cpp + cpp/pairing/* depends on intx; ported in Phase 3.
// =============================================================================

#include "kinet_crypto.h"

extern "C" int kinet_bn254_add(const uint8_t /*in*/[128], uint8_t /*out*/[64]) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_bn254_mul(const uint8_t /*in*/[96], uint8_t /*out*/[64]) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_bn254_pairing(const uint8_t* /*pairs*/, size_t /*n*/, uint8_t /*out*/[32]) {
    return KINET_ERR_NOTIMPL;
}

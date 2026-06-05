// =============================================================================
// modexp - C ABI (Phase 1 stub). cpp/modexp.cpp depends on intx + evmc.
// =============================================================================

#include "kinet_crypto.h"

extern "C" int kinet_modexp(const uint8_t* /*base*/, size_t /*base_len*/,
                          const uint8_t* /*exp*/,  size_t /*exp_len*/,
                          const uint8_t* /*mod*/,  size_t /*mod_len*/,
                          uint8_t* /*out*/) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_evm256_mulmod(const uint8_t /*a*/[32], const uint8_t /*b*/[32],
                                 const uint8_t /*m*/[32], uint8_t /*out*/[32]) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_evm256_addmod(const uint8_t /*a*/[32], const uint8_t /*b*/[32],
                                 const uint8_t /*m*/[32], uint8_t /*out*/[32]) {
    return KINET_ERR_NOTIMPL;
}

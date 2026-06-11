// =============================================================================
// evm256 — C ABI shim. Forwards extern "C" entry points to the first-party
// CPU body in cpp/evm256.cpp. No blst, no external runtime dependency beyond
// header-only intx + evmmax (vendored at crypto/deps/).
// =============================================================================

#include "crypto.h"
#include "evm256.hpp"

extern "C" int evm256_mulmod(const uint8_t a[32], const uint8_t b[32],
                             const uint8_t m[32], uint8_t out[32]) {
    return kinet::crypto::evm256::mulmod(a, b, m, out) == 0 ? CRYPTO_OK : CRYPTO_ERR_INPUT;
}

extern "C" int evm256_addmod(const uint8_t a[32], const uint8_t b[32],
                             const uint8_t m[32], uint8_t out[32]) {
    return kinet::crypto::evm256::addmod(a, b, m, out) == 0 ? CRYPTO_OK : CRYPTO_ERR_INPUT;
}

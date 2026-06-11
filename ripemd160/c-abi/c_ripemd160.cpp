// =============================================================================
// ripemd160 - C ABI implementation
// =============================================================================

#include "crypto.h"
#include "../cpp/ripemd160.hpp"

#include <cstddef>

extern "C" int ripemd160(const uint8_t* in, size_t in_len, uint8_t out[20]) {
    if (out == nullptr) return CRYPTO_ERR_INPUT;
    if (in == nullptr && in_len > 0) return CRYPTO_ERR_INPUT;
    cevm::crypto::ripemd160(reinterpret_cast<std::byte*>(out),
                            reinterpret_cast<const std::byte*>(in), in_len);
    return CRYPTO_OK;
}

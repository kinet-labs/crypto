// =============================================================================
// sha256 - C ABI implementation
// =============================================================================

#include "kinet_crypto.h"
#include "../cpp/sha256.hpp"

#include <cstddef>

extern "C" int kinet_sha256(const uint8_t* in, size_t in_len, uint8_t out[32]) {
    if (out == nullptr) return KINET_ERR_INPUT;
    cevm::crypto::sha256(reinterpret_cast<std::byte*>(out),
                         reinterpret_cast<const std::byte*>(in), in_len);
    return KINET_OK;
}

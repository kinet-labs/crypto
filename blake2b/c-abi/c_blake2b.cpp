// =============================================================================
// blake2b - C ABI implementation
// =============================================================================

#include "crypto.h"
#include "blake2b_full.hpp"

extern "C" int blake2b(const uint8_t* in, size_t in_len, uint8_t out[64]) {
    if (out == nullptr) return CRYPTO_ERR_INPUT;
    kinet::crypto::blake2b::hash(in, in_len, out);
    return CRYPTO_OK;
}

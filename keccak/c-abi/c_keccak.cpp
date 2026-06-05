// =============================================================================
// keccak - C ABI implementation
// =============================================================================
// keccak256 itself is exported by cpp/keccak.cpp (first-party body).
// This file adds the batch wrapper from the unified C ABI surface.
// =============================================================================

#include "kinet_crypto.h"
#include "kinet/crypto/keccak.h"  // first-party keccak256 declaration

extern "C" int keccak256_batch(const uint8_t* const* in,
                               const size_t* in_len,
                               size_t n,
                               uint8_t* out_flat) {
    if (out_flat == nullptr || (n > 0 && (in == nullptr || in_len == nullptr)))
        return CRYPTO_ERR_INPUT;
    for (size_t i = 0; i < n; ++i) {
        ::keccak256(in[i], in_len[i], out_flat + i * 32);
    }
    return CRYPTO_OK;
}

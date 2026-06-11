// =============================================================================
// blake3 - C ABI implementation
// =============================================================================
// Forwards to the first-party CPU body in blake3/cpp/blake3.cpp. Output is
// byte-equal to the official BLAKE3 KAT (test_vectors.json).

#include "kinet_crypto.h"
#include "../cpp/blake3.hpp"

#include <vector>

extern "C" int blake3(const uint8_t* in, size_t in_len, uint8_t out[32]) {
    if (out == nullptr) return CRYPTO_ERR_INPUT;
    kinet::crypto::blake3::hash32(in, in_len, out);
    return CRYPTO_OK;
}

extern "C" int blake3_batch(const uint8_t* const* in, const size_t* in_len,
                            size_t n, uint8_t* out_flat) {
    if (out_flat == nullptr) return CRYPTO_ERR_INPUT;
    if (n > 0 && (in == nullptr || in_len == nullptr)) return CRYPTO_ERR_INPUT;
    for (size_t i = 0; i < n; ++i) {
        kinet::crypto::blake3::hash32(in[i], in_len[i], out_flat + i * 32);
    }
    return CRYPTO_OK;
}

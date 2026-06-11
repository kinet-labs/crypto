// =============================================================================
// verkle - C ABI shim. The byte-equal commit/verify bodies are blocked on
// the IPA + Banderwagon backends; until then this returns CRYPTO_ERR_NOTIMPL
// after running input validation.
// =============================================================================

#include "kinet_crypto.h"
#include "../cpp/verkle.hpp"

extern "C" int verkle_commit(const uint8_t* coeffs, size_t n, uint8_t commit[32]) {
    if (coeffs == nullptr || commit == nullptr || n == 0) {
        return CRYPTO_ERR_INPUT;
    }
    if (n > 256) return CRYPTO_ERR_INPUT;  // Verkle node width
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int verkle_verify(const uint8_t commit[32], const uint8_t* proof,
                             size_t proof_len) {
    if (commit == nullptr || proof == nullptr || proof_len == 0) {
        return CRYPTO_ERR_INPUT;
    }
    return CRYPTO_ERR_NOTIMPL;
}

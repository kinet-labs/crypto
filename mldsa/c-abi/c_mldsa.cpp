// =============================================================================
// kinet-labs/crypto/mldsa - C-ABI shim (FIPS 204)
// =============================================================================
// Dispatches mldsa_{keygen,sign,verify} into the vendored PQClean reference
// implementation via cpp/mldsa.hpp. mode in {2,3,5} selects the FIPS 204
// parameter set (ML-DSA-44, ML-DSA-65, ML-DSA-87 respectively).
//
// The seed[32] argument to keygen is unused: PQClean's keypair generator
// pulls fresh entropy via the randombytes hook (kinet-labs/pqclean common/
// randombytes.c, getentropy(3)). The arg is kept in the signature for
// forward-compat with deterministic-keygen variants.
//
// =============================================================================

#include "crypto.h"

#include "../cpp/mldsa.hpp"

extern "C" int mldsa_keygen(int mode,
                            const uint8_t /*seed*/[32],
                            uint8_t* pk,
                            uint8_t* sk) {
    if (pk == nullptr || sk == nullptr) return CRYPTO_ERR_INPUT;
    bool ok = false;
    switch (mode) {
        case 2: ok = kinet::crypto::mldsa::keypair_44(pk, sk); break;
        case 3: ok = kinet::crypto::mldsa::keypair_65(pk, sk); break;
        case 5: ok = kinet::crypto::mldsa::keypair_87(pk, sk); break;
        default: return CRYPTO_ERR_INPUT;
    }
    return ok ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}

extern "C" int mldsa_sign(int mode,
                          const uint8_t* sk,
                          const uint8_t* msg, size_t msg_len,
                          uint8_t* sig, size_t* sig_len) {
    if (sk == nullptr || sig == nullptr || sig_len == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    bool ok = false;
    switch (mode) {
        case 2: ok = kinet::crypto::mldsa::sign_44(sig, sig_len, msg, msg_len, sk); break;
        case 3: ok = kinet::crypto::mldsa::sign_65(sig, sig_len, msg, msg_len, sk); break;
        case 5: ok = kinet::crypto::mldsa::sign_87(sig, sig_len, msg, msg_len, sk); break;
        default: return CRYPTO_ERR_INPUT;
    }
    return ok ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}

extern "C" int mldsa_verify(int mode,
                            const uint8_t* pk,
                            const uint8_t* msg, size_t msg_len,
                            const uint8_t* sig, size_t sig_len) {
    if (pk == nullptr || sig == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    if (sig_len == 0) return CRYPTO_ERR_INPUT;
    bool ok = false;
    switch (mode) {
        case 2: ok = kinet::crypto::mldsa::verify_44(sig, sig_len, msg, msg_len, pk); break;
        case 3: ok = kinet::crypto::mldsa::verify_65(sig, sig_len, msg, msg_len, pk); break;
        case 5: ok = kinet::crypto::mldsa::verify_87(sig, sig_len, msg, msg_len, pk); break;
        default: return CRYPTO_ERR_INPUT;
    }
    return ok ? CRYPTO_OK : CRYPTO_ERR_VERIFY;
}

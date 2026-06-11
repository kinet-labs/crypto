// =============================================================================
// kinet-labs/crypto/slhdsa - C-ABI shim (FIPS 205)
// =============================================================================
// Dispatches slhdsa_{keygen,sign,verify} into the vendored PQClean SLH-DSA
// reference. Mode encoding:
//   mode = 2  -> SLH-DSA-SHA2-128f  (NIST L1)
//   mode = 3  -> SLH-DSA-SHA2-192f  (NIST L3)
//   mode = 5  -> SLH-DSA-SHA2-256f  (NIST L5)
//   mode = 12 -> SLH-DSA-SHAKE-128f (NIST L1)
//   mode = 13 -> SLH-DSA-SHAKE-192f (NIST L3)
//   mode = 15 -> SLH-DSA-SHAKE-256f (NIST L5)
//
// Only the 'f' (fast) parameter sets are wired in this initial port. The 's'
// (small) variants are FIPS-defined but out of scope for the C-ABI surface.
//
// =============================================================================

#include "kinet_crypto.h"

#include "../cpp/slhdsa.hpp"

extern "C" int slhdsa_keygen(int mode,
                             const uint8_t /*seed*/[32],
                             uint8_t* pk,
                             uint8_t* sk) {
    bool ok = false;
    switch (mode) {
        case 2:  ok = kinet::crypto::slhdsa::keypair_sha2_128f(pk, sk);  break;
        case 3:  ok = kinet::crypto::slhdsa::keypair_sha2_192f(pk, sk);  break;
        case 5:  ok = kinet::crypto::slhdsa::keypair_sha2_256f(pk, sk);  break;
        case 12: ok = kinet::crypto::slhdsa::keypair_shake_128f(pk, sk); break;
        case 13: ok = kinet::crypto::slhdsa::keypair_shake_192f(pk, sk); break;
        case 15: ok = kinet::crypto::slhdsa::keypair_shake_256f(pk, sk); break;
        default: return CRYPTO_ERR_INPUT;
    }
    return ok ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}

extern "C" int slhdsa_sign(int mode,
                           const uint8_t* sk,
                           const uint8_t* msg, size_t msg_len,
                           uint8_t* sig, size_t* sig_len) {
    bool ok = false;
    switch (mode) {
        case 2:  ok = kinet::crypto::slhdsa::sign_sha2_128f(sig, sig_len, msg, msg_len, sk);  break;
        case 3:  ok = kinet::crypto::slhdsa::sign_sha2_192f(sig, sig_len, msg, msg_len, sk);  break;
        case 5:  ok = kinet::crypto::slhdsa::sign_sha2_256f(sig, sig_len, msg, msg_len, sk);  break;
        case 12: ok = kinet::crypto::slhdsa::sign_shake_128f(sig, sig_len, msg, msg_len, sk); break;
        case 13: ok = kinet::crypto::slhdsa::sign_shake_192f(sig, sig_len, msg, msg_len, sk); break;
        case 15: ok = kinet::crypto::slhdsa::sign_shake_256f(sig, sig_len, msg, msg_len, sk); break;
        default: return CRYPTO_ERR_INPUT;
    }
    return ok ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}

extern "C" int slhdsa_verify(int mode,
                             const uint8_t* pk,
                             const uint8_t* msg, size_t msg_len,
                             const uint8_t* sig, size_t sig_len) {
    bool ok = false;
    switch (mode) {
        case 2:  ok = kinet::crypto::slhdsa::verify_sha2_128f(sig, sig_len, msg, msg_len, pk);  break;
        case 3:  ok = kinet::crypto::slhdsa::verify_sha2_192f(sig, sig_len, msg, msg_len, pk);  break;
        case 5:  ok = kinet::crypto::slhdsa::verify_sha2_256f(sig, sig_len, msg, msg_len, pk);  break;
        case 12: ok = kinet::crypto::slhdsa::verify_shake_128f(sig, sig_len, msg, msg_len, pk); break;
        case 13: ok = kinet::crypto::slhdsa::verify_shake_192f(sig, sig_len, msg, msg_len, pk); break;
        case 15: ok = kinet::crypto::slhdsa::verify_shake_256f(sig, sig_len, msg, msg_len, pk); break;
        default: return CRYPTO_ERR_INPUT;
    }
    return ok ? CRYPTO_OK : CRYPTO_ERR_VERIFY;
}

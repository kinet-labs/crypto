// C-ABI shim for Lamport-SHA256 OTS. Wires the public ABI declared in
// kinet_crypto.h to the first-party CPU body in lamport/cpp/lamport.cpp.
//
// Buffer sizes (caller-owned):
//   sk : 16384 bytes (256 * 2 * 32)
//   pk : 16384 bytes (256 * 2 * 32)
//   sig:  8192 bytes (256 * 32)

#include "crypto.h"
#include "lamport.hpp"

extern "C" int lamport_keygen(const uint8_t seed[32], uint8_t* pk, uint8_t* sk) {
    if (!seed || !pk || !sk) return CRYPTO_ERR_INPUT;
    kinet::crypto::lamport::keygen(seed, sk, pk);
    return CRYPTO_OK;
}

extern "C" int lamport_sign(const uint8_t* sk, const uint8_t msg32[32], uint8_t* sig) {
    if (!sk || !msg32 || !sig) return CRYPTO_ERR_INPUT;
    kinet::crypto::lamport::sign(sk, msg32, sig);
    return CRYPTO_OK;
}

extern "C" int lamport_verify(const uint8_t* pk, const uint8_t msg32[32], const uint8_t* sig) {
    if (!pk || !msg32 || !sig) return CRYPTO_ERR_INPUT;
    return kinet::crypto::lamport::verify(pk, msg32, sig) ? CRYPTO_OK
                                                        : CRYPTO_ERR_VERIFY;
}

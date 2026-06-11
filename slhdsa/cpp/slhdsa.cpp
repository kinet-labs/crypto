// =============================================================================
// kinet-labs/crypto/slhdsa - PQClean dispatch
// =============================================================================
// Bridges kinet::crypto::slhdsa::{keypair,sign,verify}_{sha2,shake}_{128,192,
// 256}f into the six vendored PQClean SLH-DSA reference implementations under
// cpp/pqclean/sphincs-{sha2,shake}-{128,192,256}f-simple/. Each PQClean impl
// uses a unique PQCLEAN_SPHINCS{SHA2,SHAKE}{128,192,256}FSIMPLE_CLEAN_ symbol
// prefix.
// =============================================================================

#include "slhdsa.hpp"

extern "C" {
#include "sphincs-sha2-128f-simple/clean/api.h"
#include "sphincs-sha2-192f-simple/clean/api.h"
#include "sphincs-sha2-256f-simple/clean/api.h"
#include "sphincs-shake-128f-simple/clean/api.h"
#include "sphincs-shake-192f-simple/clean/api.h"
#include "sphincs-shake-256f-simple/clean/api.h"
}

namespace kinet::crypto::slhdsa {

// --- SHA2 family -------------------------------------------------------------
bool keypair_sha2_128f(std::uint8_t* pk, std::uint8_t* sk) {
    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk) == 0;
}
bool keypair_sha2_192f(std::uint8_t* pk, std::uint8_t* sk) {
    return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk) == 0;
}
bool keypair_sha2_256f(std::uint8_t* pk, std::uint8_t* sk) {
    return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk) == 0;
}

bool sign_sha2_128f(std::uint8_t* sig, std::size_t* siglen,
                    const std::uint8_t* msg, std::size_t mlen,
                    const std::uint8_t* sk) {
    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(
               sig, siglen, msg, mlen, sk) == 0;
}
bool sign_sha2_192f(std::uint8_t* sig, std::size_t* siglen,
                    const std::uint8_t* msg, std::size_t mlen,
                    const std::uint8_t* sk) {
    return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_signature(
               sig, siglen, msg, mlen, sk) == 0;
}
bool sign_sha2_256f(std::uint8_t* sig, std::size_t* siglen,
                    const std::uint8_t* msg, std::size_t mlen,
                    const std::uint8_t* sk) {
    return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_signature(
               sig, siglen, msg, mlen, sk) == 0;
}

bool verify_sha2_128f(const std::uint8_t* sig, std::size_t siglen,
                      const std::uint8_t* msg, std::size_t mlen,
                      const std::uint8_t* pk) {
    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(
               sig, siglen, msg, mlen, pk) == 0;
}
bool verify_sha2_192f(const std::uint8_t* sig, std::size_t siglen,
                      const std::uint8_t* msg, std::size_t mlen,
                      const std::uint8_t* pk) {
    return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_verify(
               sig, siglen, msg, mlen, pk) == 0;
}
bool verify_sha2_256f(const std::uint8_t* sig, std::size_t siglen,
                      const std::uint8_t* msg, std::size_t mlen,
                      const std::uint8_t* pk) {
    return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_verify(
               sig, siglen, msg, mlen, pk) == 0;
}

// --- SHAKE family ------------------------------------------------------------
bool keypair_shake_128f(std::uint8_t* pk, std::uint8_t* sk) {
    return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk) == 0;
}
bool keypair_shake_192f(std::uint8_t* pk, std::uint8_t* sk) {
    return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk) == 0;
}
bool keypair_shake_256f(std::uint8_t* pk, std::uint8_t* sk) {
    return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk) == 0;
}

bool sign_shake_128f(std::uint8_t* sig, std::size_t* siglen,
                     const std::uint8_t* msg, std::size_t mlen,
                     const std::uint8_t* sk) {
    return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature(
               sig, siglen, msg, mlen, sk) == 0;
}
bool sign_shake_192f(std::uint8_t* sig, std::size_t* siglen,
                     const std::uint8_t* msg, std::size_t mlen,
                     const std::uint8_t* sk) {
    return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_signature(
               sig, siglen, msg, mlen, sk) == 0;
}
bool sign_shake_256f(std::uint8_t* sig, std::size_t* siglen,
                     const std::uint8_t* msg, std::size_t mlen,
                     const std::uint8_t* sk) {
    return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_signature(
               sig, siglen, msg, mlen, sk) == 0;
}

bool verify_shake_128f(const std::uint8_t* sig, std::size_t siglen,
                       const std::uint8_t* msg, std::size_t mlen,
                       const std::uint8_t* pk) {
    return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify(
               sig, siglen, msg, mlen, pk) == 0;
}
bool verify_shake_192f(const std::uint8_t* sig, std::size_t siglen,
                       const std::uint8_t* msg, std::size_t mlen,
                       const std::uint8_t* pk) {
    return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_verify(
               sig, siglen, msg, mlen, pk) == 0;
}
bool verify_shake_256f(const std::uint8_t* sig, std::size_t siglen,
                       const std::uint8_t* msg, std::size_t mlen,
                       const std::uint8_t* pk) {
    return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_verify(
               sig, siglen, msg, mlen, pk) == 0;
}

}  // namespace kinet::crypto::slhdsa

// =============================================================================
// kinet-labs/crypto/mldsa - PQClean dispatch
// =============================================================================
// Bridges kinet::crypto::mldsa::{keypair,sign,verify}_{44,65,87} into the three
// PQClean ML-DSA reference implementations pulled via FetchContent from
// kinet-labs/pqclean (crypto_sign/ml-dsa-{44,65,87}/clean). The PQClean per-set
// symbols carry a unique PQCLEAN_MLDSA{44,65,87}_CLEAN_ namespace prefix so
// all three coexist in the final static library with no symbol collisions.
// =============================================================================

#include "mldsa.hpp"

extern "C" {
#include "ml-dsa-44/clean/api.h"
#include "ml-dsa-65/clean/api.h"
#include "ml-dsa-87/clean/api.h"
}

namespace kinet::crypto::mldsa {

bool keypair_44(std::uint8_t* pk, std::uint8_t* sk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk) == 0;
}
bool keypair_65(std::uint8_t* pk, std::uint8_t* sk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk) == 0;
}
bool keypair_87(std::uint8_t* pk, std::uint8_t* sk) {
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk, sk) == 0;
}

bool sign_44(std::uint8_t* sig, std::size_t* siglen,
             const std::uint8_t* msg, std::size_t mlen,
             const std::uint8_t* sk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(
               sig, siglen, msg, mlen, sk) == 0;
}
bool sign_65(std::uint8_t* sig, std::size_t* siglen,
             const std::uint8_t* msg, std::size_t mlen,
             const std::uint8_t* sk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(
               sig, siglen, msg, mlen, sk) == 0;
}
bool sign_87(std::uint8_t* sig, std::size_t* siglen,
             const std::uint8_t* msg, std::size_t mlen,
             const std::uint8_t* sk) {
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(
               sig, siglen, msg, mlen, sk) == 0;
}

bool verify_44(const std::uint8_t* sig, std::size_t siglen,
               const std::uint8_t* msg, std::size_t mlen,
               const std::uint8_t* pk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
               sig, siglen, msg, mlen, pk) == 0;
}
bool verify_65(const std::uint8_t* sig, std::size_t siglen,
               const std::uint8_t* msg, std::size_t mlen,
               const std::uint8_t* pk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
               sig, siglen, msg, mlen, pk) == 0;
}
bool verify_87(const std::uint8_t* sig, std::size_t siglen,
               const std::uint8_t* msg, std::size_t mlen,
               const std::uint8_t* pk) {
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(
               sig, siglen, msg, mlen, pk) == 0;
}

}  // namespace kinet::crypto::mldsa

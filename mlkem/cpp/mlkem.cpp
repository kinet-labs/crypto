// =============================================================================
// kinet-labs/crypto/mlkem - PQClean dispatch
// =============================================================================
// Bridges kinet::crypto::mlkem::{keypair,encap,decap}_{512,768,1024} into the
// three vendored PQClean ML-KEM reference implementations under
// cpp/pqclean/ml-kem-{512,768,1024}/. Each PQClean impl carries a unique
// PQCLEAN_MLKEM{512,768,1024}_CLEAN_ symbol prefix.
// =============================================================================

#include "mlkem.hpp"

extern "C" {
#include "pqclean/ml-kem-512/api.h"
#include "pqclean/ml-kem-768/api.h"
#include "pqclean/ml-kem-1024/api.h"
}

namespace kinet::crypto::mlkem {

bool keypair_512(std::uint8_t* pk, std::uint8_t* sk) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk) == 0;
}
bool keypair_768(std::uint8_t* pk, std::uint8_t* sk) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk) == 0;
}
bool keypair_1024(std::uint8_t* pk, std::uint8_t* sk) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pk, sk) == 0;
}

bool encap_512(std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk) == 0;
}
bool encap_768(std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk) == 0;
}
bool encap_1024(std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct, ss, pk) == 0;
}

bool decap_512(std::uint8_t* ss, const std::uint8_t* ct, const std::uint8_t* sk) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk) == 0;
}
bool decap_768(std::uint8_t* ss, const std::uint8_t* ct, const std::uint8_t* sk) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk) == 0;
}
bool decap_1024(std::uint8_t* ss, const std::uint8_t* ct, const std::uint8_t* sk) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss, ct, sk) == 0;
}

}  // namespace kinet::crypto::mlkem

#include "kinet_crypto.h"

extern "C" int aead_chacha20poly1305_seal(
    const uint8_t /*key*/[32], const uint8_t /*nonce*/[12],
    const uint8_t* /*aad*/, size_t /*aad_len*/,
    const uint8_t* /*pt*/, size_t /*pt_len*/,
    uint8_t* /*ct*/, uint8_t /*tag*/[16]) {
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int aead_chacha20poly1305_open(
    const uint8_t /*key*/[32], const uint8_t /*nonce*/[12],
    const uint8_t* /*aad*/, size_t /*aad_len*/,
    const uint8_t* /*ct*/, size_t /*ct_len*/,
    const uint8_t /*tag*/[16],
    uint8_t* /*pt*/) {
    return CRYPTO_ERR_NOTIMPL;
}

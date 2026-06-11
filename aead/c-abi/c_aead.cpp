// =============================================================================
// aead - C ABI implementation
// =============================================================================
//
// Dispatches the public C ABI surface (declared in kinet_crypto.h) to the
// first-party body in cpp/aead.cpp:
//   * ChaCha20-Poly1305 (RFC 8439)
//   * AES-256-GCM       (NIST SP 800-38D, 96-bit IV)
// =============================================================================

#include "crypto.h"
#include "../cpp/aead.hpp"

extern "C" int aead_chacha20poly1305_seal(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct, uint8_t tag[16]) {
    if (key == nullptr || nonce == nullptr || tag == nullptr) {
        return CRYPTO_ERR_INPUT;
    }
    if (pt_len > 0 && (pt == nullptr || ct == nullptr)) {
        return CRYPTO_ERR_INPUT;
    }
    if (aad_len > 0 && aad == nullptr) {
        return CRYPTO_ERR_INPUT;
    }
    const bool ok = kinet::crypto::aead::chacha20_poly1305::encrypt(
        key, nonce, aad, aad_len, pt, pt_len, ct, tag);
    return ok ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}

extern "C" int aead_chacha20poly1305_open(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    const uint8_t tag[16],
    uint8_t* pt) {
    if (key == nullptr || nonce == nullptr || tag == nullptr) {
        return CRYPTO_ERR_INPUT;
    }
    if (ct_len > 0 && (ct == nullptr || pt == nullptr)) {
        return CRYPTO_ERR_INPUT;
    }
    if (aad_len > 0 && aad == nullptr) {
        return CRYPTO_ERR_INPUT;
    }
    const bool ok = kinet::crypto::aead::chacha20_poly1305::decrypt(
        key, nonce, aad, aad_len, ct, ct_len, tag, pt);
    return ok ? CRYPTO_OK : CRYPTO_ERR_VERIFY;
}

extern "C" int aead_aes_256_gcm_seal(
    const uint8_t key[32], const uint8_t iv[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct, uint8_t tag[16]) {
    if (key == nullptr || iv == nullptr || tag == nullptr) {
        return CRYPTO_ERR_INPUT;
    }
    if (pt_len > 0 && (pt == nullptr || ct == nullptr)) {
        return CRYPTO_ERR_INPUT;
    }
    if (aad_len > 0 && aad == nullptr) {
        return CRYPTO_ERR_INPUT;
    }
    const bool ok = kinet::crypto::aead::aes_256_gcm::encrypt(
        key, iv, aad, aad_len, pt, pt_len, ct, tag);
    return ok ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}

extern "C" int aead_aes_256_gcm_open(
    const uint8_t key[32], const uint8_t iv[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    const uint8_t tag[16],
    uint8_t* pt) {
    if (key == nullptr || iv == nullptr || tag == nullptr) {
        return CRYPTO_ERR_INPUT;
    }
    if (ct_len > 0 && (ct == nullptr || pt == nullptr)) {
        return CRYPTO_ERR_INPUT;
    }
    if (aad_len > 0 && aad == nullptr) {
        return CRYPTO_ERR_INPUT;
    }
    const bool ok = kinet::crypto::aead::aes_256_gcm::decrypt(
        key, iv, aad, aad_len, ct, ct_len, tag, pt);
    return ok ? CRYPTO_OK : CRYPTO_ERR_VERIFY;
}

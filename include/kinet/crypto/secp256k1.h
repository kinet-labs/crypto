/* Copyright (c) 2024-2026 Kinet Industries Inc.
 * SPDX-License-Identifier: BSD-3-Clause-Eco
 *
 * kinet_crypto secp256k1 — first-party C ABI.
 *
 * No external crypto libraries. No vendored code. No runtime dependencies.
 *
 * Single source of truth used by:
 *   - Go via CGO (kinet-labs/crypto/secp256k1)
 *   - Rust via FFI (kinet-crypto-sys)
 *   - C++ (kinet::crypto::secp256k1 namespace)
 *   - GPU drivers (Metal/CUDA/WGSL kernels)
 */

#ifndef KINET_CRYPTO_SECP256K1_H
#define KINET_CRYPTO_SECP256K1_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes */
typedef enum {
    KINET_SECP256K1_OK             = 0,
    KINET_SECP256K1_ERR_INVALID_R  = 1, /* r not in [1, n-1] */
    KINET_SECP256K1_ERR_INVALID_S  = 2, /* s not in [1, n-1] */
    KINET_SECP256K1_ERR_INVALID_V  = 3, /* recovery id not 0/1 */
    KINET_SECP256K1_ERR_NO_SQRT    = 4, /* x has no point on curve */
    KINET_SECP256K1_ERR_AT_INFINITY= 5, /* recovered Q == O */
    KINET_SECP256K1_ERR_NULL_ARG   = 6,
    KINET_SECP256K1_ERR_BUFFER_LEN = 7
} kinet_secp256k1_status;

/*
 * ECDSA public key recovery.
 *
 *   hash[32]   : message digest, big-endian
 *   r[32]      : signature r component, big-endian
 *   s[32]      : signature s component, big-endian
 *   v          : recovery id in {0, 1}
 *   pubkey[64] : output uncompressed public key (X || Y), big-endian
 *
 * Returns KINET_SECP256K1_OK on success. Output buffer untouched on error.
 */
kinet_secp256k1_status kinet_secp256k1_ecrecover(
    const uint8_t hash[32],
    const uint8_t r[32],
    const uint8_t s[32],
    uint8_t v,
    uint8_t pubkey[64]);

/*
 * Verify a public key recovers correctly. Used as a self-check helper:
 * recovers (r,s,v,hash) and asserts equal to expected_pubkey[64].
 */
kinet_secp256k1_status kinet_secp256k1_ecrecover_verify(
    const uint8_t hash[32],
    const uint8_t r[32],
    const uint8_t s[32],
    uint8_t v,
    const uint8_t expected_pubkey[64]);

/*
 * Batch ecrecover.
 *
 *   inputs : array of (hash || r || s || v_byte) tuples, each 97 bytes
 *   n      : number of tuples
 *   out_pk : array of n*64 bytes for recovered uncompressed public keys
 *   out_st : per-tuple status, n bytes (0 = ok, nonzero = error code)
 *
 * Always returns KINET_SECP256K1_OK if arguments are well-formed; per-tuple
 * errors are written to out_st.
 *
 * On the GPU path this dispatches one thread per tuple.
 */
kinet_secp256k1_status kinet_secp256k1_ecrecover_batch(
    const uint8_t* inputs,
    size_t n,
    uint8_t* out_pk,
    uint8_t* out_st);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* KINET_CRYPTO_SECP256K1_H */

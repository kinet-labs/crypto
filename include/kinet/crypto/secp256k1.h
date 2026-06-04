/* Copyright (c) 2024-2026 Kinet Industries Inc.
 * SPDX-License-Identifier: BSD-3-Clause-Eco
 *
 * secp256k1 — first-party C ABI.
 *
 * No external crypto libraries. No vendored code. No runtime dependencies.
 *
 * Single source of truth used by:
 *   - Go via CGO (kinet-labs/crypto/secp256k1)
 *   - Rust via FFI (kinet-crypto-sys)
 *   - C++ (kinet::crypto::secp256k1 namespace)
 *   - GPU drivers (Metal/CUDA/WGSL kernels)
 *
 * Symbols are brand-neutral; the brand lives in the include path.
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
    SECP256K1_OK             = 0,
    SECP256K1_ERR_INVALID_R  = 1, /* r not in [1, n-1] */
    SECP256K1_ERR_INVALID_S  = 2, /* s not in [1, n-1] */
    SECP256K1_ERR_INVALID_V  = 3, /* recovery id not 0/1 */
    SECP256K1_ERR_NO_SQRT    = 4, /* x has no point on curve */
    SECP256K1_ERR_AT_INFINITY= 5, /* recovered Q == O */
    SECP256K1_ERR_NULL_ARG   = 6,
    SECP256K1_ERR_BUFFER_LEN = 7
} secp256k1_status;

/*
 * ECDSA public key recovery.
 *
 *   hash[32]   : message digest, big-endian
 *   r[32]      : signature r component, big-endian
 *   s[32]      : signature s component, big-endian
 *   v          : recovery id in {0, 1}
 *   pubkey[64] : output uncompressed public key (X || Y), big-endian
 *
 * Returns SECP256K1_OK on success. Output buffer untouched on error.
 */
secp256k1_status secp256k1_ecrecover(
    const uint8_t hash[32],
    const uint8_t r[32],
    const uint8_t s[32],
    uint8_t v,
    uint8_t pubkey[64]);

/*
 * Verify a public key recovers correctly. Used as a self-check helper:
 * recovers (r,s,v,hash) and asserts equal to expected_pubkey[64].
 */
secp256k1_status secp256k1_ecrecover_verify(
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
 * Always returns SECP256K1_OK if arguments are well-formed; per-tuple
 * errors are written to out_st.
 *
 * On the GPU path this dispatches one thread per tuple.
 */
secp256k1_status secp256k1_ecrecover_batch(
    const uint8_t* inputs,
    size_t n,
    uint8_t* out_pk,
    uint8_t* out_st);

/*
 * Pipeline-based batch ecrecover. Identical input/output shape to
 * secp256k1_ecrecover_batch above (97-byte tuples, 64-byte pubkeys),
 * but internally uses the v0.63 7-stage pipeline:
 *
 *   parse_reject -> field_normalize -> recover_R -> batch_invert(r in Fn) ->
 *   scalar_mult(u1*G + u2*R, windowed table) -> batch_invert(Z in Fp) ->
 *   compose_output
 *
 * The Montgomery batch inversion (one Fermat exponentiation across the whole
 * batch instead of one per signature) is the source of the speedup over
 * secp256k1_ecrecover_batch.
 */
secp256k1_status secp256k1_ecrecover_batch_pipeline(
    const uint8_t* inputs,
    size_t n,
    uint8_t* out_pk,
    uint8_t* out_st);

/*
 * Pipeline-based batch ecrecover that emits 20-byte Ethereum addresses
 * (last 20 bytes of keccak256(uncompressed pubkey)).
 *
 *   hashes   : n*32 bytes
 *   sigs     : n*65 bytes (r||s||v)
 *   out_addr : n*20 bytes
 *   out_st   : n bytes
 */
secp256k1_status secp256k1_ecrecover_address_batch(
    size_t n,
    const uint8_t* hashes,
    const uint8_t* sigs,
    uint8_t* out_addr,
    uint8_t* out_st);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* KINET_CRYPTO_SECP256K1_H */

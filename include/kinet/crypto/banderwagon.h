// =============================================================================
// kinet-labs/crypto/banderwagon -- public C ABI
// =============================================================================
//
// Banderwagon is the prime-order subgroup of Bandersnatch (twisted Edwards over
// BLS12-381 Fr). Used as the underlying group for IPA, Pedersen vector
// commitments, and Verkle trees (EIP-7805 / Ethereum stateless work).
//
// Encoding: 32-byte compressed form (canonical big-endian X with Y-sign
// folded into +-X). 64-byte uncompressed form for trusted contexts.
//
// Determinism: every CPU and GPU code path returns byte-identical output for
// any given input. Tested in test/banderwagon_kat_test.cpp.
//
// =============================================================================

#ifndef KINET_CRYPTO_BANDERWAGON_H
#define KINET_CRYPTO_BANDERWAGON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Returns 0 on success, CRYPTO_ERR_INPUT (-1) on malformed input,
// CRYPTO_ERR_VERIFY (-3) if subgroup check fails on decode.

// Compressed serialise/deserialise (32 bytes).
int banderwagon_encode(const uint8_t point_in[64], uint8_t out[32]);
int banderwagon_decode(const uint8_t in[32], uint8_t point_out[64]);

// Group operations on uncompressed (X || Y) representation.
int banderwagon_add(const uint8_t a[64], const uint8_t b[64], uint8_t out[64]);
int banderwagon_double(const uint8_t a[64], uint8_t out[64]);
int banderwagon_neg(const uint8_t a[64], uint8_t out[64]);

// Scalar multiplication: scalar is canonical big-endian Fr (32 bytes).
int banderwagon_scalar_mul(
    const uint8_t scalar[32], const uint8_t point[64], uint8_t out[64]);

// Multi-scalar multiplication.
//   points : n * 64 bytes (uncompressed X || Y)
//   scalars: n * 32 bytes (canonical big-endian Fr)
//   out    : 64 bytes (uncompressed X || Y)
int banderwagon_msm(
    const uint8_t* points,
    const uint8_t* scalars,
    size_t n,
    uint8_t out[64]);

// Convenience: MSM on compressed-input, compressed-output.
int banderwagon_msm_compressed(
    const uint8_t* points_compressed,    // n * 32
    const uint8_t* scalars,              // n * 32
    size_t n,
    uint8_t out_compressed[32]);

// Generator and identity in uncompressed form.
void banderwagon_generator(uint8_t out[64]);
void banderwagon_identity(uint8_t out[64]);

// Equality test (Banderwagon prime-subgroup-pair semantics).
// Returns 1 if equal, 0 if not, negative on parse error.
int banderwagon_equal(const uint8_t a[64], const uint8_t b[64]);

#ifdef __cplusplus
}
#endif

#endif  // KINET_CRYPTO_BANDERWAGON_H

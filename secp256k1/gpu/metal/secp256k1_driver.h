// =============================================================================
// Kinet Crypto Library - secp256k1 GPU Acceleration
// =============================================================================
//
// GPU-accelerated secp256k1 elliptic curve operations using Metal/CUDA.
// Implements precomputed GTable approach from CudaBrainSecp for ~20x speedup.
//
// Use cases:
// - ECDSA signature verification (batch)
// - Schnorr signatures (BIP340)
// - Threshold ECDSA (CGGMP21/FROST/LSS)
// - Address derivation from public keys
//
// The GTable approach:
// - Precomputes 16 chunks × 65536 points each (~67MB table)
// - Scalar multiplication via 16 lookups + 15 additions
// - Much faster than double-and-add for random scalars
//
// Copyright (C) 2024-2025 Kinet Industries Inc.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Constants
// =============================================================================

// secp256k1 curve parameters
// Prime: p = 2^256 - 2^32 - 977
// Order: n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

#define SECP256K1_FIELD_SIZE     32  // 256 bits = 32 bytes
#define SECP256K1_SCALAR_SIZE    32  // Scalar field size
#define SECP256K1_PUBKEY_SIZE    33  // Compressed public key
#define SECP256K1_PUBKEY_UNCOMPRESSED_SIZE 65  // Uncompressed public key
#define SECP256K1_SIGNATURE_SIZE 64  // ECDSA signature (r, s)
#define SECP256K1_RECOVERABLE_SIG_SIZE 65  // Recoverable signature (r, s, v)

// GTable precomputation parameters (from CudaBrainSecp)
#define SECP256K1_GTABLE_CHUNKS    16    // 256 bits / 16 = 16 bits per chunk
#define SECP256K1_GTABLE_CHUNK_SIZE 65536 // 2^16 points per chunk
#define SECP256K1_GTABLE_TOTAL_POINTS (SECP256K1_GTABLE_CHUNKS * SECP256K1_GTABLE_CHUNK_SIZE)

// =============================================================================
// Types
// =============================================================================

/**
 * 256-bit field element (modular arithmetic mod p)
 * Stored in little-endian limb order
 */
typedef struct {
    uint64_t limbs[4];
} Secp256k1Fp;

/**
 * 256-bit scalar (modular arithmetic mod n)
 */
typedef struct {
    uint64_t limbs[4];
} Secp256k1Scalar;

/**
 * Affine point on secp256k1
 * For point at infinity: infinity = true
 */
typedef struct {
    Secp256k1Fp x;
    Secp256k1Fp y;
    bool infinity;
} Secp256k1Affine;

/**
 * Jacobian projective point on secp256k1
 * (x, y, z) represents affine (x/z^2, y/z^3)
 */
typedef struct {
    Secp256k1Fp x;
    Secp256k1Fp y;
    Secp256k1Fp z;
} Secp256k1Jacobian;

/**
 * ECDSA signature (r, s)
 */
typedef struct {
    Secp256k1Scalar r;
    Secp256k1Scalar s;
} Secp256k1Signature;

/**
 * Recoverable ECDSA signature (r, s, recovery_id)
 */
typedef struct {
    Secp256k1Scalar r;
    Secp256k1Scalar s;
    uint8_t recovery_id;  // 0-3
} Secp256k1RecoverableSignature;

/**
 * Opaque GPU context handle
 */
typedef struct MetalSecp256k1Context MetalSecp256k1Context;

// =============================================================================
// Context Management
// =============================================================================

/**
 * Create GPU context with precomputed GTable.
 * This allocates ~67MB of GPU memory for the precomputed table.
 * @param device_id GPU device ID (0 for default)
 * @return Context handle, or NULL on error
 */
MetalSecp256k1Context* metal_secp256k1_create(int device_id);

/**
 * Destroy GPU context and free resources.
 */
void metal_secp256k1_destroy(MetalSecp256k1Context* ctx);

/**
 * Check if GPU acceleration is available for secp256k1.
 * @return true if Metal/CUDA is available
 */
bool metal_secp256k1_gpu_available(void);

/**
 * Get GPU memory usage for secp256k1 operations.
 * @param ctx Context handle
 * @return Memory usage in bytes
 */
size_t metal_secp256k1_memory_usage(MetalSecp256k1Context* ctx);

// =============================================================================
// Scalar Multiplication (GTable-accelerated)
// =============================================================================

/**
 * Compute scalar multiplication: result = scalar * G
 * Uses precomputed GTable for ~20x speedup over double-and-add.
 *
 * @param ctx GPU context with precomputed GTable
 * @param result Output point (affine)
 * @param scalar 256-bit scalar
 * @return 0 on success
 */
int metal_secp256k1_scalar_mul_g(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* result,
    const Secp256k1Scalar* scalar
);

/**
 * Batch scalar multiplication: results[i] = scalars[i] * G
 * Highly parallelized on GPU.
 *
 * @param ctx GPU context
 * @param results Output points (caller allocates count elements)
 * @param scalars Array of scalars
 * @param count Number of multiplications
 * @return 0 on success
 */
int metal_secp256k1_batch_scalar_mul_g(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* results,
    const Secp256k1Scalar* scalars,
    uint32_t count
);

/**
 * General scalar multiplication: result = scalar * point
 * Uses double-and-add for arbitrary base points.
 * For base point G, use metal_secp256k1_scalar_mul_g instead.
 *
 * @param ctx GPU context
 * @param result Output point
 * @param scalar 256-bit scalar
 * @param point Base point
 * @return 0 on success
 */
int metal_secp256k1_scalar_mul(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* result,
    const Secp256k1Scalar* scalar,
    const Secp256k1Affine* point
);

/**
 * Batch general scalar multiplication: results[i] = scalars[i] * points[i]
 *
 * @param ctx GPU context
 * @param results Output points
 * @param scalars Array of scalars
 * @param points Array of base points
 * @param count Number of multiplications
 * @return 0 on success
 */
int metal_secp256k1_batch_scalar_mul(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* results,
    const Secp256k1Scalar* scalars,
    const Secp256k1Affine* points,
    uint32_t count
);

// =============================================================================
// Multi-Scalar Multiplication (MSM)
// =============================================================================

/**
 * Multi-scalar multiplication: result = sum(scalars[i] * points[i])
 * Uses Pippenger's algorithm with GPU parallelization.
 *
 * @param ctx GPU context
 * @param result Output point
 * @param points Array of base points
 * @param scalars Array of scalars
 * @param count Number of terms
 * @return 0 on success
 */
int metal_secp256k1_msm(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* result,
    const Secp256k1Affine* points,
    const Secp256k1Scalar* scalars,
    uint32_t count
);

// =============================================================================
// ECDSA Operations
// =============================================================================

/**
 * Batch ECDSA signature verification.
 * Verifies multiple (message, signature, public_key) tuples in parallel.
 *
 * @param ctx GPU context
 * @param results Output array of verification results (1=valid, 0=invalid)
 * @param messages Array of 32-byte message hashes
 * @param signatures Array of signatures
 * @param public_keys Array of public keys
 * @param count Number of signatures
 * @return 0 on success, negative on error
 */
int metal_secp256k1_batch_verify(
    MetalSecp256k1Context* ctx,
    int* results,
    const uint8_t* const* messages,  // Each 32 bytes
    const Secp256k1Signature* signatures,
    const Secp256k1Affine* public_keys,
    uint32_t count
);

/**
 * Batch ECDSA signing.
 * Signs multiple messages with multiple secret keys in parallel.
 *
 * @param ctx GPU context
 * @param signatures Output signatures
 * @param messages Array of 32-byte message hashes
 * @param secret_keys Array of secret keys (scalars)
 * @param count Number of signatures
 * @return 0 on success
 */
int metal_secp256k1_batch_sign(
    MetalSecp256k1Context* ctx,
    Secp256k1Signature* signatures,
    const uint8_t* const* messages,
    const Secp256k1Scalar* secret_keys,
    uint32_t count
);

/**
 * Batch public key recovery from signatures.
 * Recovers public keys from recoverable signatures in parallel.
 *
 * @param ctx GPU context
 * @param public_keys Output public keys
 * @param messages Array of 32-byte message hashes
 * @param signatures Array of recoverable signatures
 * @param count Number of recoveries
 * @return 0 on success
 */
int metal_secp256k1_batch_recover(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* public_keys,
    const uint8_t* const* messages,
    const Secp256k1RecoverableSignature* signatures,
    uint32_t count
);

// =============================================================================
// Schnorr (BIP340) Operations
// =============================================================================

/**
 * Batch Schnorr signature verification (BIP340).
 *
 * @param ctx GPU context
 * @param results Output verification results
 * @param messages Array of 32-byte message hashes
 * @param signatures Array of 64-byte Schnorr signatures
 * @param public_keys Array of 32-byte x-only public keys
 * @param count Number of signatures
 * @return 0 on success
 */
int metal_secp256k1_schnorr_batch_verify(
    MetalSecp256k1Context* ctx,
    int* results,
    const uint8_t* const* messages,
    const uint8_t* const* signatures,
    const uint8_t* const* public_keys,
    uint32_t count
);

// =============================================================================
// Key Derivation
// =============================================================================

/**
 * Batch derive public keys from secret keys: pk[i] = sk[i] * G
 * Uses GTable for efficient derivation.
 *
 * @param ctx GPU context
 * @param public_keys Output public keys
 * @param secret_keys Array of secret keys
 * @param count Number of keys
 * @return 0 on success
 */
int metal_secp256k1_batch_derive_pubkey(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* public_keys,
    const Secp256k1Scalar* secret_keys,
    uint32_t count
);

/**
 * Batch derive Ethereum addresses from public keys.
 * Computes keccak256(pubkey)[12:] for each public key.
 *
 * @param ctx GPU context
 * @param addresses Output addresses (20 bytes each)
 * @param public_keys Array of public keys
 * @param count Number of addresses
 * @return 0 on success
 */
int metal_secp256k1_batch_derive_address(
    MetalSecp256k1Context* ctx,
    uint8_t* addresses,  // count * 20 bytes
    const Secp256k1Affine* public_keys,
    uint32_t count
);

// =============================================================================
// Threshold ECDSA Support
// =============================================================================

/**
 * Batch nonce generation for threshold ECDSA.
 * Generates k values and computes R = k * G.
 *
 * @param ctx GPU context
 * @param r_points Output R points
 * @param k_values Output nonce values
 * @param entropy Random entropy for nonce generation
 * @param count Number of nonces
 * @return 0 on success
 */
int metal_secp256k1_batch_nonce_gen(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* r_points,
    Secp256k1Scalar* k_values,
    const uint8_t* entropy,
    uint32_t count
);

/**
 * Batch partial signature combination.
 * Combines threshold signature shares into final signatures.
 *
 * @param ctx GPU context
 * @param signatures Output combined signatures
 * @param partial_sigs Array of partial signature arrays
 * @param num_shares Number of shares per signature
 * @param count Number of signatures
 * @return 0 on success
 */
int metal_secp256k1_combine_partial_sigs(
    MetalSecp256k1Context* ctx,
    Secp256k1Signature* signatures,
    const Secp256k1Scalar* const* partial_sigs,
    uint32_t num_shares,
    uint32_t count
);

// =============================================================================
// Point Arithmetic (for custom protocols)
// =============================================================================

/**
 * Batch point addition: results[i] = a[i] + b[i]
 */
int metal_secp256k1_batch_add(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* results,
    const Secp256k1Affine* a,
    const Secp256k1Affine* b,
    uint32_t count
);

/**
 * Batch point doubling: results[i] = 2 * points[i]
 */
int metal_secp256k1_batch_double(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* results,
    const Secp256k1Affine* points,
    uint32_t count
);

/**
 * Batch point negation: results[i] = -points[i]
 */
int metal_secp256k1_batch_negate(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* results,
    const Secp256k1Affine* points,
    uint32_t count
);

// =============================================================================
// Serialization
// =============================================================================

/**
 * Serialize affine point to compressed public key (33 bytes).
 */
void secp256k1_affine_serialize_compressed(
    uint8_t* out,  // 33 bytes
    const Secp256k1Affine* point
);

/**
 * Serialize affine point to uncompressed public key (65 bytes).
 */
void secp256k1_affine_serialize_uncompressed(
    uint8_t* out,  // 65 bytes
    const Secp256k1Affine* point
);

/**
 * Deserialize compressed public key to affine point.
 * @return 0 on success, -1 if invalid
 */
int secp256k1_affine_deserialize_compressed(
    Secp256k1Affine* point,
    const uint8_t* in  // 33 bytes
);

/**
 * Deserialize uncompressed public key to affine point.
 * @return 0 on success, -1 if invalid
 */
int secp256k1_affine_deserialize_uncompressed(
    Secp256k1Affine* point,
    const uint8_t* in  // 65 bytes
);

// =============================================================================
// GTable Utilities
// =============================================================================

/**
 * Precompute GTable for custom base point.
 * Useful for protocols with fixed base points other than G.
 *
 * @param ctx GPU context
 * @param table_id Output table ID for later use
 * @param base Base point for table
 * @return 0 on success
 */
int metal_secp256k1_precompute_table(
    MetalSecp256k1Context* ctx,
    uint32_t* table_id,
    const Secp256k1Affine* base
);

/**
 * Scalar multiply using custom precomputed table.
 */
int metal_secp256k1_scalar_mul_table(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* result,
    uint32_t table_id,
    const Secp256k1Scalar* scalar
);

/**
 * Free custom precomputed table.
 */
void metal_secp256k1_free_table(
    MetalSecp256k1Context* ctx,
    uint32_t table_id
);

// =============================================================================
// Error Codes
// =============================================================================

#define SECP256K1_SUCCESS           0
#define SECP256K1_ERROR_NULL_PTR   -1
#define SECP256K1_ERROR_INVALID    -2
#define SECP256K1_ERROR_GPU        -3
#define SECP256K1_ERROR_MEMORY     -4
#define SECP256K1_ERROR_NOT_ON_CURVE -5

#ifdef __cplusplus
}
#endif

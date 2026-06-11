// =============================================================================
// Kinet ZK - GPU-Accelerated Zero-Knowledge Operations
// =============================================================================
//
// Unified C interface for ZK operations with automatic backend selection:
// - Metal (Apple Silicon via MLX)
// - CUDA (NVIDIA via MLX)
// - Optimized CPU fallback
//
// Operations:
// - Poseidon2 hash (BN254/Fr) for Merkle trees
// - Multi-scalar multiplication (MSM) for commitments
// - Batch commitment/nullifier operations
//
// Threshold-gated routing:
// - Below threshold: CPU (lower latency for small batches)
// - Above threshold: GPU (higher throughput for large batches)
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
// ZK Context Management (Backend-Agnostic)
// =============================================================================

/**
 * Opaque handle to ZK compute context.
 * Internally uses Metal, CUDA, or CPU depending on availability.
 */
typedef struct ZKContext ZKContext;

/**
 * Backend type for ZK operations.
 */
typedef enum {
    ZK_BACKEND_CPU = 0,
    ZK_BACKEND_METAL = 1,
    ZK_BACKEND_CUDA = 2,
} ZKBackend;

/**
 * Initialize ZK context with automatic backend selection.
 * Loads shaders and creates compute pipelines for:
 * - poseidon2_bn254: Poseidon2 hash over BN254/Fr
 * - msm: Multi-scalar multiplication
 * - bn254: BN254 point operations
 * @return Context handle, or NULL on error
 */
ZKContext* zk_init(void);

/**
 * Destroy ZK context and release resources.
 */
void zk_destroy(ZKContext* ctx);

/**
 * Check if GPU acceleration is available.
 * @return true if Metal or CUDA is available
 */
bool zk_gpu_available(void);

/**
 * Get the active backend.
 * @param ctx ZK context (or NULL for global check)
 * @return Backend type
 */
ZKBackend zk_get_backend(ZKContext* ctx);

/**
 * Get the backend name as a string.
 * @param ctx ZK context (or NULL for global check)
 * @return "Metal", "CUDA", or "CPU"
 */
const char* zk_get_backend_name(ZKContext* ctx);

/**
 * Get recommended threshold for GPU offload.
 * Operations below this count are faster on CPU.
 * @param op_type Operation type (see ZK_OP_* constants)
 * @return Recommended threshold count
 */
uint32_t zk_get_threshold(int op_type);

// Operation type constants for threshold queries
#define ZK_OP_POSEIDON2_HASH   1
#define ZK_OP_MERKLE_LAYER     2
#define ZK_OP_MSM              3
#define ZK_OP_COMMITMENT       4
#define ZK_OP_NULLIFIER        5
#define ZK_OP_FRI              6

// =============================================================================
// Field Element Types (256-bit, BN254 scalar field)
// =============================================================================

/**
 * 256-bit field element (4 x 64-bit limbs, little-endian).
 * Represents element in BN254 scalar field Fr.
 */
typedef struct {
    uint64_t limbs[4];
} Fr256;

/**
 * BN254 G1 affine point (x, y coordinates + infinity flag).
 * Uses 256-bit Fp coordinates.
 */
typedef struct {
    uint64_t x[4];
    uint64_t y[4];
    bool infinity;
    uint8_t _pad[7];
} G1Affine254;

/**
 * BN254 G1 projective point (Jacobian coordinates).
 */
typedef struct {
    uint64_t x[4];
    uint64_t y[4];
    uint64_t z[4];
} G1Projective254;

// =============================================================================
// Poseidon2 Hash Operations (BN254/Fr)
// =============================================================================

/**
 * Batch Poseidon2 hash on GPU.
 * Hashes pairs of field elements (2-to-1 compression).
 *
 * @param ctx ZK context
 * @param output Output hashes (count elements)
 * @param left Left input elements (count elements)
 * @param right Right input elements (count elements)
 * @param count Number of hash operations
 * @return 0 on success, negative on error
 */
int zk_poseidon2_hash_pair(
    ZKContext* ctx,
    Fr256* output,
    const Fr256* left,
    const Fr256* right,
    uint32_t count);

/**
 * Poseidon2 Merkle tree layer on GPU.
 * Computes one layer of Merkle tree from leaf pairs.
 *
 * @param ctx ZK context
 * @param output Output parent nodes (current_size/2 elements)
 * @param current_layer Current layer nodes (current_size elements)
 * @param current_size Size of current layer (must be even)
 * @return 0 on success, negative on error
 */
int zk_poseidon2_merkle_layer(
    ZKContext* ctx,
    Fr256* output,
    const Fr256* current_layer,
    uint32_t current_size);

/**
 * Build complete Poseidon2 Merkle tree on GPU.
 * Returns all internal nodes including root.
 *
 * @param ctx ZK context
 * @param tree Output tree (num_leaves - 1 internal nodes)
 * @param leaves Input leaves (num_leaves elements, must be power of 2)
 * @param num_leaves Number of leaves
 * @return 0 on success, negative on error
 */
int zk_poseidon2_merkle_tree(
    ZKContext* ctx,
    Fr256* tree,
    const Fr256* leaves,
    uint32_t num_leaves);

/**
 * Verify Poseidon2 Merkle proofs in batch.
 *
 * @param ctx ZK context
 * @param results Output: 1 if valid, 0 if invalid (count elements)
 * @param leaves Leaf values to verify (count elements)
 * @param paths Merkle paths (count * path_len elements)
 * @param indices Path directions: 0=left, 1=right (count * path_len elements)
 * @param roots Expected roots (count elements)
 * @param count Number of proofs
 * @param path_len Depth of tree (path length)
 * @return 0 on success (check results for validity), negative on error
 */
int zk_poseidon2_verify_proofs(
    ZKContext* ctx,
    int* results,
    const Fr256* leaves,
    const Fr256* paths,
    const uint32_t* indices,
    const Fr256* roots,
    uint32_t count,
    uint32_t path_len);

// =============================================================================
// Multi-Scalar Multiplication (MSM) for BN254
// =============================================================================

/**
 * Multi-scalar multiplication on GPU.
 * Computes: result = sum_i (scalars[i] * points[i])
 *
 * @param ctx ZK context
 * @param result Output point (single point)
 * @param points Input affine points (count elements)
 * @param scalars 256-bit scalars as Fr256 (count elements)
 * @param count Number of point-scalar pairs
 * @return 0 on success, negative on error
 */
int zk_msm(
    ZKContext* ctx,
    G1Projective254* result,
    const G1Affine254* points,
    const Fr256* scalars,
    uint32_t count);

/**
 * Batch scalar multiplication on GPU.
 * Computes: results[i] = scalars[i] * points[i] for all i
 *
 * @param ctx ZK context
 * @param results Output points (count elements)
 * @param points Input affine points (count elements)
 * @param scalars Input scalars (count elements)
 * @param count Number of operations
 * @return 0 on success, negative on error
 */
int zk_batch_scalar_mul(
    ZKContext* ctx,
    G1Projective254* results,
    const G1Affine254* points,
    const Fr256* scalars,
    uint32_t count);

// =============================================================================
// Commitment and Nullifier Operations
// =============================================================================

/**
 * Batch Pedersen-style commitments using Poseidon2.
 * Computes: output[i] = Poseidon2(value[i], blinding[i], salt[i])
 *
 * @param ctx ZK context
 * @param output Output commitments (count elements)
 * @param values Input values (count elements)
 * @param blindings Blinding factors (count elements)
 * @param salts Salt values (count elements)
 * @param count Number of commitments
 * @return 0 on success, negative on error
 */
int zk_batch_commitment(
    ZKContext* ctx,
    Fr256* output,
    const Fr256* values,
    const Fr256* blindings,
    const Fr256* salts,
    uint32_t count);

/**
 * Batch nullifier computation.
 * Computes: output[i] = Poseidon2(key[i], commitment[i], index[i])
 *
 * @param ctx ZK context
 * @param output Output nullifiers (count elements)
 * @param keys Nullifier keys (count elements)
 * @param commitments Note commitments (count elements)
 * @param indices Leaf indices (count elements)
 * @param count Number of nullifiers
 * @return 0 on success, negative on error
 */
int zk_batch_nullifier(
    ZKContext* ctx,
    Fr256* output,
    const Fr256* keys,
    const Fr256* commitments,
    const Fr256* indices,
    uint32_t count);

// =============================================================================
// Goldilocks Field Operations (for STARK FRI)
// =============================================================================

/**
 * 64-bit Goldilocks field element.
 * Field: p = 2^64 - 2^32 + 1
 */
typedef uint64_t GoldilocksElem;

/**
 * Goldilocks extension field element (quadratic).
 */
typedef struct {
    GoldilocksElem a;  // Real part
    GoldilocksElem b;  // Imaginary part
} GoldilocksExt;

/**
 * FRI folding layer on GPU.
 * Folds evaluation points for FRI protocol.
 *
 * @param ctx ZK context
 * @param folded Output folded evaluations (layer_size/2 elements)
 * @param evals Current layer evaluations (layer_size elements)
 * @param alpha Folding challenge
 * @param omega_inv Inverse of subgroup generator
 * @param layer_size Size of current layer
 * @return 0 on success, negative on error
 */
int zk_fri_fold_layer(
    ZKContext* ctx,
    GoldilocksElem* folded,
    const GoldilocksElem* evals,
    GoldilocksElem alpha,
    GoldilocksElem omega_inv,
    uint32_t layer_size);

/**
 * Batch Goldilocks field operations on GPU.
 * Computes: output[i] = a[i] * b[i] for all i
 *
 * @param ctx ZK context
 * @param output Output products (count elements)
 * @param a First operands (count elements)
 * @param b Second operands (count elements)
 * @param count Number of operations
 * @return 0 on success, negative on error
 */
int zk_goldilocks_batch_mul(
    ZKContext* ctx,
    GoldilocksElem* output,
    const GoldilocksElem* a,
    const GoldilocksElem* b,
    uint32_t count);

// =============================================================================
// Error Codes
// =============================================================================

#define ZK_SUCCESS            0
#define ZK_ERROR_NO_DEVICE   -1
#define ZK_ERROR_NO_SHADER   -2
#define ZK_ERROR_ALLOC       -3
#define ZK_ERROR_NULL_PTR    -4
#define ZK_ERROR_INVALID     -5
#define ZK_ERROR_SIZE        -6
#define ZK_ERROR_BACKEND     -7

// =============================================================================
// Threshold Constants (recommended batch sizes for GPU)
// =============================================================================

// Below these thresholds, CPU is faster due to GPU overhead
#define ZK_THRESHOLD_POSEIDON2     64   // 64 hashes
#define ZK_THRESHOLD_MERKLE       128   // 128 leaf pairs
#define ZK_THRESHOLD_MSM          256   // 256 point-scalar pairs
#define ZK_THRESHOLD_COMMITMENT   128   // 128 commitments
#define ZK_THRESHOLD_FRI          512   // 512 FRI evaluations

// =============================================================================
// Backward Compatibility (deprecated - use zk_* functions)
// =============================================================================

// Aliases for old metal_zk_* API
#define MetalZKContext ZKContext
#define metal_zk_init zk_init
#define metal_zk_destroy zk_destroy
#define metal_zk_available zk_gpu_available
#define metal_zk_get_threshold zk_get_threshold
#define metal_zk_poseidon2_hash_pair zk_poseidon2_hash_pair
#define metal_zk_poseidon2_merkle_layer zk_poseidon2_merkle_layer
#define metal_zk_poseidon2_merkle_tree zk_poseidon2_merkle_tree
#define metal_zk_poseidon2_verify_proofs zk_poseidon2_verify_proofs
#define metal_zk_msm zk_msm
#define metal_zk_batch_scalar_mul zk_batch_scalar_mul
#define metal_zk_batch_commitment zk_batch_commitment
#define metal_zk_batch_nullifier zk_batch_nullifier
#define metal_zk_fri_fold_layer zk_fri_fold_layer
#define metal_zk_goldilocks_batch_mul zk_goldilocks_batch_mul

// Old error codes
#define METAL_ZK_SUCCESS ZK_SUCCESS
#define METAL_ZK_ERROR_NO_DEVICE ZK_ERROR_NO_DEVICE
#define METAL_ZK_ERROR_NO_SHADER ZK_ERROR_NO_SHADER
#define METAL_ZK_ERROR_ALLOC ZK_ERROR_ALLOC
#define METAL_ZK_ERROR_NULL_PTR ZK_ERROR_NULL_PTR
#define METAL_ZK_ERROR_INVALID ZK_ERROR_INVALID
#define METAL_ZK_ERROR_SIZE ZK_ERROR_SIZE

// Old operation types
#define METAL_ZK_OP_POSEIDON2_HASH ZK_OP_POSEIDON2_HASH
#define METAL_ZK_OP_MERKLE_LAYER ZK_OP_MERKLE_LAYER
#define METAL_ZK_OP_MSM ZK_OP_MSM
#define METAL_ZK_OP_COMMITMENT ZK_OP_COMMITMENT
#define METAL_ZK_OP_NULLIFIER ZK_OP_NULLIFIER

// Old thresholds
#define METAL_ZK_THRESHOLD_POSEIDON2 ZK_THRESHOLD_POSEIDON2
#define METAL_ZK_THRESHOLD_MERKLE ZK_THRESHOLD_MERKLE
#define METAL_ZK_THRESHOLD_MSM ZK_THRESHOLD_MSM
#define METAL_ZK_THRESHOLD_COMMITMENT ZK_THRESHOLD_COMMITMENT
#define METAL_ZK_THRESHOLD_FRI ZK_THRESHOLD_FRI

#ifdef __cplusplus
}
#endif

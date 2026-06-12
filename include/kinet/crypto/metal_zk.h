// =============================================================================
// Metal ZK - GPU Acceleration for Zero-Knowledge Operations
// =============================================================================
//
// C interface for dispatching ZK operations to Metal compute shaders:
// - Poseidon2 hash (BN254/Fr) for Merkle trees
// - Multi-scalar multiplication (MSM) for commitments
// - Batch commitment/nullifier operations
//
// These operations are designed for batch execution with threshold gates:
// - Below threshold: CPU execution (lower latency)
// - Above threshold: GPU execution (higher throughput)
//

#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Metal ZK Context Management
// =============================================================================

/**
 * Opaque handle to Metal ZK compute context.
 */
typedef struct MetalZKContext MetalZKContext;

/**
 * Initialize Metal ZK context.
 * Loads shaders and creates compute pipelines for:
 * - poseidon2_bn254: Poseidon2 hash over BN254/Fr
 * - msm: Multi-scalar multiplication
 * - bn254: BN254 point operations
 * @return Context handle, or NULL if Metal unavailable
 */
MetalZKContext* metal_zk_init(void);

/**
 * Destroy Metal ZK context and release resources.
 */
void metal_zk_destroy(MetalZKContext* ctx);

/**
 * Check if Metal ZK acceleration is available.
 * @return true if Metal GPU is available
 */
bool metal_zk_available(void);

/**
 * Get recommended threshold for GPU offload.
 * Operations below this count are faster on CPU.
 * @param op_type Operation type (see METAL_ZK_OP_* constants)
 * @return Recommended threshold count
 */
uint32_t metal_zk_get_threshold(int op_type);

// Operation type constants for threshold queries
#define METAL_ZK_OP_POSEIDON2_HASH   1
#define METAL_ZK_OP_MERKLE_LAYER     2
#define METAL_ZK_OP_MSM              3
#define METAL_ZK_OP_COMMITMENT       4
#define METAL_ZK_OP_NULLIFIER        5

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
 * @param ctx Metal ZK context
 * @param output Output hashes (count elements)
 * @param left Left input elements (count elements)
 * @param right Right input elements (count elements)
 * @param count Number of hash operations
 * @return 0 on success, negative on error
 */
int metal_zk_poseidon2_hash_pair(
    MetalZKContext* ctx,
    Fr256* output,
    const Fr256* left,
    const Fr256* right,
    uint32_t count);

/**
 * Poseidon2 Merkle tree layer on GPU.
 * Computes one layer of Merkle tree from leaf pairs.
 *
 * @param ctx Metal ZK context
 * @param output Output parent nodes (current_size/2 elements)
 * @param current_layer Current layer nodes (current_size elements)
 * @param current_size Size of current layer (must be even)
 * @return 0 on success, negative on error
 */
int metal_zk_poseidon2_merkle_layer(
    MetalZKContext* ctx,
    Fr256* output,
    const Fr256* current_layer,
    uint32_t current_size);

/**
 * Build complete Poseidon2 Merkle tree on GPU.
 * Returns all internal nodes including root.
 *
 * @param ctx Metal ZK context
 * @param tree Output tree (num_leaves - 1 internal nodes)
 * @param leaves Input leaves (num_leaves elements, must be power of 2)
 * @param num_leaves Number of leaves
 * @return 0 on success, negative on error
 */
int metal_zk_poseidon2_merkle_tree(
    MetalZKContext* ctx,
    Fr256* tree,
    const Fr256* leaves,
    uint32_t num_leaves);

/**
 * Verify Poseidon2 Merkle proofs in batch.
 *
 * @param ctx Metal ZK context
 * @param results Output: 1 if valid, 0 if invalid (count elements)
 * @param leaves Leaf values to verify (count elements)
 * @param paths Merkle paths (count * path_len elements)
 * @param indices Path directions: 0=left, 1=right (count * path_len elements)
 * @param roots Expected roots (count elements)
 * @param count Number of proofs
 * @param path_len Depth of tree (path length)
 * @return 0 on success (check results for validity), negative on error
 */
int metal_zk_poseidon2_verify_proofs(
    MetalZKContext* ctx,
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
 * @param ctx Metal ZK context
 * @param result Output point (single point)
 * @param points Input affine points (count elements)
 * @param scalars 256-bit scalars as Fr256 (count elements)
 * @param count Number of point-scalar pairs
 * @return 0 on success, negative on error
 */
int metal_zk_msm(
    MetalZKContext* ctx,
    G1Projective254* result,
    const G1Affine254* points,
    const Fr256* scalars,
    uint32_t count);

/**
 * Batch scalar multiplication on GPU.
 * Computes: results[i] = scalars[i] * points[i] for all i
 *
 * @param ctx Metal ZK context
 * @param results Output points (count elements)
 * @param points Input affine points (count elements)
 * @param scalars Input scalars (count elements)
 * @param count Number of operations
 * @return 0 on success, negative on error
 */
int metal_zk_batch_scalar_mul(
    MetalZKContext* ctx,
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
 * @param ctx Metal ZK context
 * @param output Output commitments (count elements)
 * @param values Input values (count elements)
 * @param blindings Blinding factors (count elements)
 * @param salts Salt values (count elements)
 * @param count Number of commitments
 * @return 0 on success, negative on error
 */
int metal_zk_batch_commitment(
    MetalZKContext* ctx,
    Fr256* output,
    const Fr256* values,
    const Fr256* blindings,
    const Fr256* salts,
    uint32_t count);

/**
 * Batch nullifier computation.
 * Computes: output[i] = Poseidon2(key[i], commitment[i], index[i])
 *
 * @param ctx Metal ZK context
 * @param output Output nullifiers (count elements)
 * @param keys Nullifier keys (count elements)
 * @param commitments Note commitments (count elements)
 * @param indices Leaf indices (count elements)
 * @param count Number of nullifiers
 * @return 0 on success, negative on error
 */
int metal_zk_batch_nullifier(
    MetalZKContext* ctx,
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
 * @param ctx Metal ZK context
 * @param folded Output folded evaluations (layer_size/2 elements)
 * @param evals Current layer evaluations (layer_size elements)
 * @param alpha Folding challenge
 * @param omega_inv Inverse of subgroup generator
 * @param layer_size Size of current layer
 * @return 0 on success, negative on error
 */
int metal_zk_fri_fold_layer(
    MetalZKContext* ctx,
    GoldilocksElem* folded,
    const GoldilocksElem* evals,
    GoldilocksElem alpha,
    GoldilocksElem omega_inv,
    uint32_t layer_size);

/**
 * Batch Goldilocks field operations on GPU.
 * Computes: output[i] = a[i] * b[i] for all i
 *
 * @param ctx Metal ZK context
 * @param output Output products (count elements)
 * @param a First operands (count elements)
 * @param b Second operands (count elements)
 * @param count Number of operations
 * @return 0 on success, negative on error
 */
int metal_zk_goldilocks_batch_mul(
    MetalZKContext* ctx,
    GoldilocksElem* output,
    const GoldilocksElem* a,
    const GoldilocksElem* b,
    uint32_t count);

// =============================================================================
// Error Codes
// =============================================================================

#define METAL_ZK_SUCCESS            0
#define METAL_ZK_ERROR_NO_DEVICE   -1
#define METAL_ZK_ERROR_NO_SHADER   -2
#define METAL_ZK_ERROR_ALLOC       -3
#define METAL_ZK_ERROR_NULL_PTR    -4
#define METAL_ZK_ERROR_INVALID     -5
#define METAL_ZK_ERROR_SIZE        -6

// =============================================================================
// Threshold Constants (recommended batch sizes for GPU)
// =============================================================================

// Below these thresholds, CPU is faster due to GPU overhead
#define METAL_ZK_THRESHOLD_POSEIDON2     64   // 64 hashes
#define METAL_ZK_THRESHOLD_MERKLE       128   // 128 leaf pairs
#define METAL_ZK_THRESHOLD_MSM          256   // 256 point-scalar pairs
#define METAL_ZK_THRESHOLD_COMMITMENT   128   // 128 commitments
#define METAL_ZK_THRESHOLD_FRI          512   // 512 FRI evaluations

#ifdef __cplusplus
}
#endif

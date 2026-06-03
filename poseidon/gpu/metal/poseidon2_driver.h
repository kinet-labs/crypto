// =============================================================================
// Metal Poseidon2 - GPU Acceleration for ZK-Friendly Hash
// =============================================================================
//
// Poseidon2 hash function optimized for zero-knowledge proof systems.
// Native field arithmetic over BN254 and BLS12-381 scalar fields.
//

#ifndef KINET_METAL_POSEIDON2_H
#define KINET_METAL_POSEIDON2_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Context Management
// =============================================================================

typedef struct MetalPoseidon2Context MetalPoseidon2Context;

MetalPoseidon2Context* metal_poseidon2_init(void);
void metal_poseidon2_destroy(MetalPoseidon2Context* ctx);
bool metal_poseidon2_available(void);

// =============================================================================
// Field Selection
// =============================================================================

typedef enum {
    POSEIDON2_BN254 = 0,      // BN254 scalar field (254 bits)
    POSEIDON2_BLS12_381 = 1,  // BLS12-381 scalar field (255 bits)
    POSEIDON2_GOLDILOCKS = 2, // Goldilocks field (64 bits) - Plonky2
    POSEIDON2_M31 = 3,        // Mersenne-31 field - Plonky3/Circle STARKs
} Poseidon2Field;

// =============================================================================
// Field Element Types
// =============================================================================

/** BN254/BLS12-381 field element (4 x 64-bit limbs) */
typedef struct {
    uint64_t limbs[4];
} Poseidon2Fe256;

/** Goldilocks field element (single 64-bit) */
typedef uint64_t Poseidon2FeGoldilocks;

/** M31 field element (single 32-bit) */
typedef uint32_t Poseidon2FeM31;

// =============================================================================
// Return Codes
// =============================================================================

typedef enum {
    METAL_POSEIDON2_SUCCESS = 0,
    METAL_POSEIDON2_ERROR_INIT = -1,
    METAL_POSEIDON2_ERROR_INVALID_INPUT = -2,
    METAL_POSEIDON2_ERROR_GPU_DISPATCH = -3,
} MetalPoseidon2Result;

// =============================================================================
// Hash Functions
// =============================================================================

/**
 * Poseidon2 hash with configurable width and field.
 *
 * @param ctx       Metal context
 * @param field     Field to use
 * @param output    Output hash (single field element)
 * @param inputs    Input field elements
 * @param count     Number of inputs (1 to width-1)
 * @param width     State width (2, 3, 4, 8, 12, 16)
 */
MetalPoseidon2Result metal_poseidon2_hash(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    void* output,
    const void* inputs,
    uint32_t count,
    uint32_t width
);

/**
 * Batch Poseidon2 hash - hash multiple inputs in parallel.
 * Extremely efficient on GPU.
 *
 * @param ctx           Metal context
 * @param field         Field to use
 * @param outputs       Output hashes array
 * @param inputs        Input arrays (flattened)
 * @param input_counts  Number of inputs per hash
 * @param batch_size    Number of hashes to compute
 * @param width         State width
 */
MetalPoseidon2Result metal_poseidon2_batch_hash(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    void* outputs,
    const void* inputs,
    const uint32_t* input_counts,
    uint32_t batch_size,
    uint32_t width
);

// =============================================================================
// Merkle Tree Operations
// =============================================================================

/**
 * Compute Poseidon2 Merkle root from leaves.
 *
 * @param ctx       Metal context
 * @param field     Field to use
 * @param root      Output root
 * @param leaves    Leaf values
 * @param count     Number of leaves (must be power of 2)
 */
MetalPoseidon2Result metal_poseidon2_merkle_root(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    void* root,
    const void* leaves,
    uint32_t count
);

/**
 * Build full Merkle tree and return all nodes.
 *
 * @param ctx       Metal context
 * @param field     Field to use
 * @param nodes     Output nodes (2*count - 1 elements)
 * @param leaves    Leaf values
 * @param count     Number of leaves (power of 2)
 */
MetalPoseidon2Result metal_poseidon2_merkle_tree(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    void* nodes,
    const void* leaves,
    uint32_t count
);

/**
 * Compute Merkle proof for a leaf.
 *
 * @param ctx       Metal context
 * @param field     Field to use
 * @param proof     Output proof (log2(count) siblings)
 * @param nodes     Full tree nodes
 * @param leaf_idx  Index of leaf
 * @param count     Number of leaves
 */
MetalPoseidon2Result metal_poseidon2_merkle_proof(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    void* proof,
    const void* nodes,
    uint32_t leaf_idx,
    uint32_t count
);

/**
 * Verify Merkle proof.
 */
MetalPoseidon2Result metal_poseidon2_merkle_verify(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    const void* root,
    const void* leaf,
    const void* proof,
    uint32_t leaf_idx,
    uint32_t depth
);

// =============================================================================
// Sponge Construction
// =============================================================================

typedef struct MetalPoseidon2Sponge MetalPoseidon2Sponge;

/**
 * Create new sponge state.
 */
MetalPoseidon2Sponge* metal_poseidon2_sponge_new(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    uint32_t width
);

/**
 * Absorb data into sponge.
 */
MetalPoseidon2Result metal_poseidon2_sponge_absorb(
    MetalPoseidon2Sponge* sponge,
    const void* data,
    uint32_t count
);

/**
 * Squeeze output from sponge.
 */
MetalPoseidon2Result metal_poseidon2_sponge_squeeze(
    MetalPoseidon2Sponge* sponge,
    void* output,
    uint32_t count
);

/**
 * Free sponge state.
 */
void metal_poseidon2_sponge_free(MetalPoseidon2Sponge* sponge);

// =============================================================================
// Compression Function (for recursive proofs)
// =============================================================================

/**
 * Two-to-one compression: H(left, right).
 */
MetalPoseidon2Result metal_poseidon2_compress(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    void* output,
    const void* left,
    const void* right
);

/**
 * Batch compression - parallel two-to-one hash.
 */
MetalPoseidon2Result metal_poseidon2_batch_compress(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    void* outputs,
    const void* lefts,
    const void* rights,
    uint32_t count
);

#ifdef __cplusplus
}
#endif

#endif // KINET_METAL_POSEIDON2_H

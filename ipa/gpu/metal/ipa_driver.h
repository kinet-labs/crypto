// =============================================================================
// Metal IPA - GPU Acceleration for Verkle Trees
// =============================================================================
//
// C++ interface for Verkle tree operations using Inner Product Arguments (IPA).
// GPU-accelerated Banderwagon curve operations and multi-scalar multiplication.
//

#ifndef KINET_METAL_IPA_H
#define KINET_METAL_IPA_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Metal Context Management
// =============================================================================

typedef struct MetalIPAContext MetalIPAContext;

/**
 * Initialize Metal IPA context with precomputed generators.
 * @return Context handle, or NULL if Metal unavailable
 */
MetalIPAContext* metal_ipa_init(void);

/**
 * Destroy Metal IPA context and release resources.
 */
void metal_ipa_destroy(MetalIPAContext* ctx);

/**
 * Check if Metal IPA acceleration is available.
 */
bool metal_ipa_available(void);

// =============================================================================
// Banderwagon Curve Types (embedded in BLS12-381)
// =============================================================================

/** 253-bit scalar field element (Fr) - 4 x 64-bit limbs */
typedef struct {
    uint64_t limbs[4];
} BanderwagonScalar;

/** Banderwagon affine point */
typedef struct {
    uint64_t x[4];  // 256-bit x coordinate
    uint64_t y[4];  // 256-bit y coordinate
} BanderwagonAffine;

/** Banderwagon extended point (for faster addition) */
typedef struct {
    uint64_t x[4];
    uint64_t y[4];
    uint64_t t[4];  // x*y
    uint64_t z[4];
} BanderwagonExtended;

// =============================================================================
// Return Codes
// =============================================================================

typedef enum {
    METAL_IPA_SUCCESS = 0,
    METAL_IPA_ERROR_INIT = -1,
    METAL_IPA_ERROR_INVALID_INPUT = -2,
    METAL_IPA_ERROR_GPU_DISPATCH = -3,
    METAL_IPA_ERROR_PROOF_INVALID = -4,
} MetalIPAResult;

// =============================================================================
// Multi-Scalar Multiplication (MSM) - Core Verkle Operation
// =============================================================================

/**
 * Batch multi-scalar multiplication: result = sum(scalars[i] * points[i])
 * This is the core operation for Verkle tree commitment computation.
 *
 * @param ctx       Metal context
 * @param result    Output point (affine)
 * @param scalars   Array of scalars
 * @param points    Array of points (affine)
 * @param count     Number of scalar-point pairs
 * @return METAL_IPA_SUCCESS on success
 */
MetalIPAResult metal_ipa_msm(
    MetalIPAContext* ctx,
    BanderwagonAffine* result,
    const BanderwagonScalar* scalars,
    const BanderwagonAffine* points,
    uint32_t count
);

/**
 * Batch MSM for multiple independent computations.
 * Useful for computing multiple Verkle commitments in parallel.
 *
 * @param ctx           Metal context
 * @param results       Array of output points
 * @param scalars       2D array of scalars [batch_size][vector_size]
 * @param points        Shared basis points
 * @param batch_size    Number of independent MSMs
 * @param vector_size   Size of each scalar/point vector
 */
MetalIPAResult metal_ipa_batch_msm(
    MetalIPAContext* ctx,
    BanderwagonAffine* results,
    const BanderwagonScalar* scalars,
    const BanderwagonAffine* points,
    uint32_t batch_size,
    uint32_t vector_size
);

// =============================================================================
// Pedersen Commitment Operations
// =============================================================================

/**
 * Compute Pedersen vector commitment: C = sum(v[i] * G[i]) + r * H
 *
 * @param ctx       Metal context
 * @param result    Output commitment point
 * @param values    Vector of values to commit
 * @param blinding  Blinding factor (NULL for deterministic)
 * @param count     Vector length
 */
MetalIPAResult metal_ipa_pedersen_commit(
    MetalIPAContext* ctx,
    BanderwagonAffine* result,
    const BanderwagonScalar* values,
    const BanderwagonScalar* blinding,
    uint32_t count
);

/**
 * Batch Pedersen commitments for multiple vectors.
 */
MetalIPAResult metal_ipa_batch_pedersen_commit(
    MetalIPAContext* ctx,
    BanderwagonAffine* results,
    const BanderwagonScalar* values,
    const BanderwagonScalar* blindings,
    uint32_t batch_size,
    uint32_t vector_size
);

// =============================================================================
// IPA Proof Generation and Verification
// =============================================================================

/** IPA proof structure */
typedef struct {
    BanderwagonAffine L[8];     // Left commitments (log2 of max vector size)
    BanderwagonAffine R[8];     // Right commitments
    BanderwagonScalar a;        // Final scalar a
    uint32_t num_rounds;        // Number of IPA rounds used
} IPAProof;

/**
 * Generate IPA proof for inner product relation.
 * Proves that <a, b> = c for committed vectors.
 *
 * @param ctx           Metal context
 * @param proof         Output proof
 * @param commitment    Pedersen commitment to vector a
 * @param a_vec         Vector a
 * @param b_vec         Vector b (public)
 * @param inner_product The claimed inner product <a, b>
 * @param vector_size   Size of vectors (must be power of 2)
 */
MetalIPAResult metal_ipa_prove(
    MetalIPAContext* ctx,
    IPAProof* proof,
    const BanderwagonAffine* commitment,
    const BanderwagonScalar* a_vec,
    const BanderwagonScalar* b_vec,
    const BanderwagonScalar* inner_product,
    uint32_t vector_size
);

/**
 * Verify IPA proof.
 *
 * @param ctx           Metal context
 * @param proof         Proof to verify
 * @param commitment    Pedersen commitment
 * @param b_vec         Public vector b
 * @param inner_product Claimed inner product
 * @param vector_size   Vector size
 * @return METAL_IPA_SUCCESS if valid
 */
MetalIPAResult metal_ipa_verify(
    MetalIPAContext* ctx,
    const IPAProof* proof,
    const BanderwagonAffine* commitment,
    const BanderwagonScalar* b_vec,
    const BanderwagonScalar* inner_product,
    uint32_t vector_size
);

/**
 * Batch verify multiple IPA proofs.
 * More efficient than individual verification.
 */
MetalIPAResult metal_ipa_batch_verify(
    MetalIPAContext* ctx,
    const IPAProof* proofs,
    const BanderwagonAffine* commitments,
    const BanderwagonScalar* b_vecs,
    const BanderwagonScalar* inner_products,
    uint32_t proof_count,
    uint32_t vector_size,
    bool* results
);

// =============================================================================
// Verkle Tree Specific Operations
// =============================================================================

/** Verkle node width (256 children per node) */
#define VERKLE_WIDTH 256

/**
 * Compute Verkle tree node commitment from child commitments.
 *
 * @param ctx           Metal context
 * @param result        Output node commitment
 * @param children      Array of 256 child commitments (NULL for empty)
 * @param stem          32-byte stem value
 */
MetalIPAResult metal_verkle_commit_node(
    MetalIPAContext* ctx,
    BanderwagonAffine* result,
    const BanderwagonAffine* children,
    const uint8_t* stem
);

/**
 * Batch compute multiple Verkle node commitments.
 */
MetalIPAResult metal_verkle_batch_commit_nodes(
    MetalIPAContext* ctx,
    BanderwagonAffine* results,
    const BanderwagonAffine* children_array,
    const uint8_t* stems,
    uint32_t node_count
);

/**
 * Compute leaf value commitment for Verkle tree.
 *
 * @param ctx       Metal context
 * @param result    Output commitment
 * @param values    Array of 256 32-byte values
 * @param stem      32-byte stem
 */
MetalIPAResult metal_verkle_commit_leaf(
    MetalIPAContext* ctx,
    BanderwagonAffine* result,
    const uint8_t values[256][32],
    const uint8_t* stem
);

// =============================================================================
// Point Arithmetic (GPU-accelerated)
// =============================================================================

/**
 * Batch point addition.
 */
MetalIPAResult metal_ipa_batch_add(
    MetalIPAContext* ctx,
    BanderwagonAffine* results,
    const BanderwagonAffine* points_a,
    const BanderwagonAffine* points_b,
    uint32_t count
);

/**
 * Batch scalar multiplication.
 */
MetalIPAResult metal_ipa_batch_scalar_mul(
    MetalIPAContext* ctx,
    BanderwagonAffine* results,
    const BanderwagonScalar* scalars,
    const BanderwagonAffine* points,
    uint32_t count
);

/**
 * Serialize point to 32 bytes (compressed).
 */
void metal_ipa_point_serialize(
    uint8_t out[32],
    const BanderwagonAffine* point
);

/**
 * Deserialize point from 32 bytes.
 */
MetalIPAResult metal_ipa_point_deserialize(
    BanderwagonAffine* point,
    const uint8_t in[32]
);

#ifdef __cplusplus
}
#endif

#endif // KINET_METAL_IPA_H

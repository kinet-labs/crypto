// =============================================================================
// Metal BLS12-381 - GPU Acceleration Interface
// =============================================================================
//
// C++ interface for dispatching BLS12-381 operations to Metal compute shaders.
// Provides batch operations for signature verification and key aggregation.
//

#ifndef KINET_METAL_BLS_H
#define KINET_METAL_BLS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Metal Context Management
// =============================================================================

/**
 * Opaque handle to Metal compute context.
 */
typedef struct MetalBLSContext MetalBLSContext;

/**
 * Initialize Metal BLS context.
 * Loads shaders and creates compute pipelines.
 * @return Context handle, or NULL if Metal unavailable
 */
MetalBLSContext* metal_bls_init(void);

/**
 * Destroy Metal BLS context and release resources.
 */
void metal_bls_destroy(MetalBLSContext* ctx);

/**
 * Check if Metal acceleration is available.
 * @return true if Metal GPU is available
 */
bool metal_bls_available(void);

// =============================================================================
// Field Element Types (384-bit)
// =============================================================================

/**
 * 384-bit field element (6 x 64-bit limbs, little-endian).
 */
typedef struct {
    uint64_t limbs[6];
} Fp384;

/**
 * G1 affine point (x, y coordinates + infinity flag).
 */
typedef struct {
    Fp384 x;
    Fp384 y;
    bool infinity;
    uint8_t _pad[7];  // Alignment padding
} G1Affine;

/**
 * G1 projective point (Jacobian coordinates).
 */
typedef struct {
    Fp384 x;
    Fp384 y;
    Fp384 z;
} G1Projective;

// =============================================================================
// Batch Point Operations
// =============================================================================

/**
 * Batch point addition on GPU.
 * Computes: results[i] = a[i] + b[i] for all i.
 * @param ctx Metal context
 * @param results Output array (count elements)
 * @param a First input array (count elements)
 * @param b Second input array (count elements)
 * @param count Number of additions
 * @return 0 on success, negative on error
 */
int metal_bls_batch_add(
    MetalBLSContext* ctx,
    G1Projective* results,
    const G1Projective* a,
    const G1Projective* b,
    uint32_t count);

/**
 * Batch point doubling on GPU.
 * Computes: results[i] = 2 * points[i] for all i.
 * @param ctx Metal context
 * @param results Output array (count elements)
 * @param points Input array (count elements)
 * @param count Number of doublings
 * @return 0 on success, negative on error
 */
int metal_bls_batch_double(
    MetalBLSContext* ctx,
    G1Projective* results,
    const G1Projective* points,
    uint32_t count);

/**
 * Batch scalar multiplication on GPU.
 * Computes: results[i] = scalars[i] * points[i] for all i.
 * @param ctx Metal context
 * @param results Output array (count elements)
 * @param points Input array (count elements)
 * @param scalars 256-bit scalars as 4x64-bit limbs each (count * 4 elements)
 * @param count Number of multiplications
 * @return 0 on success, negative on error
 */
int metal_bls_batch_scalar_mul(
    MetalBLSContext* ctx,
    G1Projective* results,
    const G1Projective* points,
    const uint64_t* scalars,
    uint32_t count);

// =============================================================================
// Multi-Scalar Multiplication (MSM)
// =============================================================================

/**
 * Multi-scalar multiplication on GPU.
 * Computes: result = sum_i (scalars[i] * points[i])
 * Optimized using bucket method for batch signature verification.
 * @param ctx Metal context
 * @param result Output single point
 * @param points Input affine points (count elements)
 * @param scalars 256-bit scalars (count * 4 limbs)
 * @param count Number of point-scalar pairs
 * @return 0 on success, negative on error
 */
int metal_bls_msm(
    MetalBLSContext* ctx,
    G1Projective* result,
    const G1Affine* points,
    const uint64_t* scalars,
    uint32_t count);

// =============================================================================
// Batch Signature Verification
// =============================================================================

/**
 * Batch verify BLS signatures using random linear combination.
 * More efficient than verifying signatures individually.
 *
 * Verification equation:
 *   e(sum_i(r_i * sig_i), G2) = e(sum_i(r_i * H(msg_i)), sum_i(r_i * pk_i))
 *
 * @param ctx Metal context
 * @param sigs Array of signatures (G2 points, 96 bytes each)
 * @param pks Array of public keys (G1 points, 48 bytes each)
 * @param msgs Array of message hashes (32 bytes each)
 * @param count Number of signatures
 * @param results Output: 1 if valid, 0 if invalid (for individual tracking)
 * @return 0 on success (all valid), negative on error, positive = invalid count
 */
int metal_bls_batch_verify(
    MetalBLSContext* ctx,
    const uint8_t* const* sigs,
    const uint8_t* const* pks,
    const uint8_t* const* msgs,
    uint32_t count,
    int* results);

/**
 * Aggregate signatures on GPU.
 * Computes: agg_sig = sum_i(sigs[i])
 * @param ctx Metal context
 * @param agg_sig Output aggregated signature (96 bytes)
 * @param sigs Array of signatures (96 bytes each)
 * @param count Number of signatures
 * @return 0 on success, negative on error
 */
int metal_bls_aggregate_sigs(
    MetalBLSContext* ctx,
    uint8_t* agg_sig,
    const uint8_t* const* sigs,
    uint32_t count);

/**
 * Aggregate public keys on GPU.
 * Computes: agg_pk = sum_i(pks[i])
 * @param ctx Metal context
 * @param agg_pk Output aggregated public key (48 bytes)
 * @param pks Array of public keys (48 bytes each)
 * @param count Number of public keys
 * @return 0 on success, negative on error
 */
int metal_bls_aggregate_pks(
    MetalBLSContext* ctx,
    uint8_t* agg_pk,
    const uint8_t* const* pks,
    uint32_t count);

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Convert affine point to projective.
 */
void metal_bls_affine_to_projective(G1Projective* proj, const G1Affine* affine);

/**
 * Convert projective point to affine (requires inversion).
 */
void metal_bls_projective_to_affine(G1Affine* affine, const G1Projective* proj);

/**
 * Deserialize compressed G1 point (48 bytes).
 */
int metal_bls_g1_decompress(G1Affine* point, const uint8_t* compressed);

/**
 * Serialize G1 point to compressed form (48 bytes).
 */
int metal_bls_g1_compress(uint8_t* compressed, const G1Affine* point);

// =============================================================================
// Error Codes
// =============================================================================

#define METAL_BLS_SUCCESS           0
#define METAL_BLS_ERROR_NO_DEVICE  -1
#define METAL_BLS_ERROR_NO_SHADER  -2
#define METAL_BLS_ERROR_ALLOC      -3
#define METAL_BLS_ERROR_NULL_PTR   -4
#define METAL_BLS_ERROR_INVALID    -5

#ifdef __cplusplus
}
#endif

#endif // KINET_METAL_BLS_H

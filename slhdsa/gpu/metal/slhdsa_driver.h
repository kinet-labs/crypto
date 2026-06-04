// =============================================================================
// Metal SLH-DSA - GPU Acceleration Interface for Hash-Based Signatures
// =============================================================================
//
// C++ interface for dispatching SLH-DSA (FIPS 205, Stateless Hash-Based
// Digital Signature Algorithm, formerly SPHINCS+) operations to Metal compute.
//
// SLH-DSA is hash-based and doesn't use NTT like ML-DSA/ML-KEM.
// GPU acceleration focuses on:
//   - Parallel hash tree computations (WOTS+, XMSS, FORS)
//   - Batch signature verification
//   - Parallel SHAKE/SHA2 operations
//

#ifndef KINET_METAL_SLHDSA_H
#define KINET_METAL_SLHDSA_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// SLH-DSA Modes
// =============================================================================

/**
 * SLH-DSA parameter sets.
 * Format: {hash}_{security}_{variant}
 * - hash: SHA2 or SHAKE
 * - security: 128, 192, or 256 bits
 * - variant: s (small signature) or f (fast signing)
 */
typedef enum {
    // 128-bit security (NIST Level 1)
    SLHDSA_SHA2_128s  = 0,
    SLHDSA_SHAKE_128s = 1,
    SLHDSA_SHA2_128f  = 2,
    SLHDSA_SHAKE_128f = 3,

    // 192-bit security (NIST Level 3)
    SLHDSA_SHA2_192s  = 4,
    SLHDSA_SHAKE_192s = 5,
    SLHDSA_SHA2_192f  = 6,
    SLHDSA_SHAKE_192f = 7,

    // 256-bit security (NIST Level 5)
    SLHDSA_SHA2_256s  = 8,
    SLHDSA_SHAKE_256s = 9,
    SLHDSA_SHA2_256f  = 10,
    SLHDSA_SHAKE_256f = 11,
} SLHDSAMode;

// =============================================================================
// Size Constants
// =============================================================================

// 128-bit small (Level 1)
#define SLHDSA_128S_PUBLIC_KEY_SIZE  32
#define SLHDSA_128S_SECRET_KEY_SIZE  64
#define SLHDSA_128S_SIGNATURE_SIZE   7856

// 128-bit fast (Level 1)
#define SLHDSA_128F_PUBLIC_KEY_SIZE  32
#define SLHDSA_128F_SECRET_KEY_SIZE  64
#define SLHDSA_128F_SIGNATURE_SIZE   17088

// 192-bit small (Level 3)
#define SLHDSA_192S_PUBLIC_KEY_SIZE  48
#define SLHDSA_192S_SECRET_KEY_SIZE  96
#define SLHDSA_192S_SIGNATURE_SIZE   16224

// 192-bit fast (Level 3)
#define SLHDSA_192F_PUBLIC_KEY_SIZE  48
#define SLHDSA_192F_SECRET_KEY_SIZE  96
#define SLHDSA_192F_SIGNATURE_SIZE   35664

// 256-bit small (Level 5)
#define SLHDSA_256S_PUBLIC_KEY_SIZE  64
#define SLHDSA_256S_SECRET_KEY_SIZE  128
#define SLHDSA_256S_SIGNATURE_SIZE   29792

// 256-bit fast (Level 5)
#define SLHDSA_256F_PUBLIC_KEY_SIZE  64
#define SLHDSA_256F_SECRET_KEY_SIZE  128
#define SLHDSA_256F_SIGNATURE_SIZE   49856

// =============================================================================
// Context Management
// =============================================================================

/**
 * Opaque handle to Metal SLH-DSA compute context.
 */
typedef struct MetalSLHDSAContext MetalSLHDSAContext;

/**
 * Initialize Metal SLH-DSA context.
 * Loads hash shaders and creates compute pipelines.
 * @return Context handle, or NULL if Metal unavailable
 */
MetalSLHDSAContext* metal_slhdsa_init(void);

/**
 * Destroy Metal SLH-DSA context and release resources.
 */
void metal_slhdsa_destroy(MetalSLHDSAContext* ctx);

/**
 * Check if Metal acceleration is available for SLH-DSA.
 * @return true if Metal GPU is available
 */
bool metal_slhdsa_available(void);

// =============================================================================
// Key Generation
// =============================================================================

/**
 * Generate SLH-DSA key pair on GPU.
 * Uses GPU-accelerated hash tree computation.
 * @param ctx Metal context
 * @param mode Parameter set
 * @param public_key Output public key buffer
 * @param secret_key Output secret key buffer
 * @param seed Random seed (n bytes where n = 16/24/32 for 128/192/256-bit)
 * @return 0 on success, negative on error
 */
int metal_slhdsa_keygen(
    MetalSLHDSAContext* ctx,
    SLHDSAMode mode,
    uint8_t* public_key,
    uint8_t* secret_key,
    const uint8_t* seed);

// =============================================================================
// Signing Operations
// =============================================================================

/**
 * Sign a message using SLH-DSA on GPU.
 * @param ctx Metal context
 * @param mode Parameter set
 * @param signature Output signature buffer
 * @param secret_key Secret key bytes
 * @param message Message to sign
 * @param message_len Message length
 * @param context Optional context string (NULL for empty)
 * @param context_len Context string length
 * @return 0 on success, negative on error
 */
int metal_slhdsa_sign(
    MetalSLHDSAContext* ctx,
    SLHDSAMode mode,
    uint8_t* signature,
    const uint8_t* secret_key,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* context,
    size_t context_len);

/**
 * Batch sign multiple messages on GPU.
 * All messages use the same secret key.
 * @param ctx Metal context
 * @param mode Parameter set
 * @param signatures Output signature buffers (count elements)
 * @param secret_key Secret key bytes
 * @param messages Array of message pointers
 * @param message_lens Array of message lengths
 * @param count Number of messages to sign
 * @return 0 on success, negative on error
 */
int metal_slhdsa_batch_sign(
    MetalSLHDSAContext* ctx,
    SLHDSAMode mode,
    uint8_t** signatures,
    const uint8_t* secret_key,
    const uint8_t* const* messages,
    const size_t* message_lens,
    uint32_t count);

// =============================================================================
// Verification Operations
// =============================================================================

/**
 * Verify an SLH-DSA signature on GPU.
 * @param ctx Metal context
 * @param mode Parameter set
 * @param public_key Public key bytes
 * @param signature Signature bytes
 * @param message Message that was signed
 * @param message_len Message length
 * @param context Optional context string
 * @param context_len Context string length
 * @return 1 if valid, 0 if invalid, negative on error
 */
int metal_slhdsa_verify(
    MetalSLHDSAContext* ctx,
    SLHDSAMode mode,
    const uint8_t* public_key,
    const uint8_t* signature,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* context,
    size_t context_len);

/**
 * Batch verify multiple SLH-DSA signatures on GPU.
 * Significantly faster than individual verification for large batches.
 * @param ctx Metal context
 * @param mode Parameter set
 * @param public_keys Array of public keys
 * @param signatures Array of signatures
 * @param messages Array of message pointers
 * @param message_lens Array of message lengths
 * @param count Number of signatures to verify
 * @param results Output: 1 if valid, 0 if invalid (count elements)
 * @return Number of valid signatures, negative on error
 */
int metal_slhdsa_batch_verify(
    MetalSLHDSAContext* ctx,
    SLHDSAMode mode,
    const uint8_t* const* public_keys,
    const uint8_t* const* signatures,
    const uint8_t* const* messages,
    const size_t* message_lens,
    uint32_t count,
    int* results);

// =============================================================================
// Error Codes
// =============================================================================

#define METAL_SLHDSA_SUCCESS           0
#define METAL_SLHDSA_ERROR_NO_DEVICE  -1
#define METAL_SLHDSA_ERROR_NO_SHADER  -2
#define METAL_SLHDSA_ERROR_ALLOC      -3
#define METAL_SLHDSA_ERROR_NULL_PTR   -4
#define METAL_SLHDSA_ERROR_INVALID    -5
#define METAL_SLHDSA_ERROR_VERIFY     -6

#ifdef __cplusplus
}
#endif

#endif // KINET_METAL_SLHDSA_H

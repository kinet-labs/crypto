// =============================================================================
// Metal ML-DSA - GPU Acceleration Interface for Post-Quantum Signatures
// =============================================================================
//
// C++ interface for dispatching ML-DSA (FIPS 204, Module-Lattice Digital
// Signature Algorithm) operations to Metal compute shaders.
//
// ML-DSA Parameters:
//   - n = 256 (polynomial degree)
//   - q = 8380417 (modulus)
//   - Levels: 44 (128-bit), 65 (192-bit), 87 (256-bit)
//
// GPU acceleration targets:
//   - NTT/INTT for polynomial multiplication
//   - Matrix-vector products
//   - Batch signature verification
//   - Batch signing operations
//

#ifndef KINET_METAL_MLDSA_H
#define KINET_METAL_MLDSA_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// ML-DSA Constants
// =============================================================================

// Ring parameters
#define MLDSA_N         256       // Polynomial degree
#define MLDSA_Q         8380417   // Modulus q
#define MLDSA_Q_BITS    23        // log2(q) rounded up

// ML-DSA-44 (NIST Level 2, 128-bit security)
#define MLDSA44_K               4
#define MLDSA44_L               4
#define MLDSA44_PUBLIC_KEY_SIZE 1312
#define MLDSA44_SECRET_KEY_SIZE 2560
#define MLDSA44_SIGNATURE_SIZE  2420

// ML-DSA-65 (NIST Level 3, 192-bit security)
#define MLDSA65_K               6
#define MLDSA65_L               5
#define MLDSA65_PUBLIC_KEY_SIZE 1952
#define MLDSA65_SECRET_KEY_SIZE 4032
#define MLDSA65_SIGNATURE_SIZE  3309

// ML-DSA-87 (NIST Level 5, 256-bit security)
#define MLDSA87_K               8
#define MLDSA87_L               7
#define MLDSA87_PUBLIC_KEY_SIZE 2592
#define MLDSA87_SECRET_KEY_SIZE 4896
#define MLDSA87_SIGNATURE_SIZE  4627

// =============================================================================
// Context Management
// =============================================================================

/**
 * Opaque handle to Metal ML-DSA compute context.
 */
typedef struct MetalMLDSAContext MetalMLDSAContext;

/**
 * ML-DSA security level.
 */
typedef enum {
    MLDSA_MODE_44 = 0,  // 128-bit security (NIST Level 2)
    MLDSA_MODE_65 = 1,  // 192-bit security (NIST Level 3)
    MLDSA_MODE_87 = 2,  // 256-bit security (NIST Level 5)
} MLDSAMode;

/**
 * Initialize Metal ML-DSA context.
 * Loads NTT shaders and creates compute pipelines.
 * @return Context handle, or NULL if Metal unavailable
 */
MetalMLDSAContext* metal_mldsa_init(void);

/**
 * Destroy Metal ML-DSA context and release resources.
 */
void metal_mldsa_destroy(MetalMLDSAContext* ctx);

/**
 * Check if Metal acceleration is available for ML-DSA.
 * @return true if Metal GPU is available
 */
bool metal_mldsa_available(void);

// =============================================================================
// Key Generation
// =============================================================================

/**
 * Generate ML-DSA key pair on GPU.
 * Uses GPU-accelerated NTT for matrix expansion.
 * @param ctx Metal context
 * @param mode Security level (44, 65, or 87)
 * @param public_key Output public key buffer
 * @param secret_key Output secret key buffer
 * @param seed 32-byte random seed
 * @return 0 on success, negative on error
 */
int metal_mldsa_keygen(
    MetalMLDSAContext* ctx,
    MLDSAMode mode,
    uint8_t* public_key,
    uint8_t* secret_key,
    const uint8_t* seed);

// =============================================================================
// Signing Operations
// =============================================================================

/**
 * Sign a message using ML-DSA on GPU.
 * @param ctx Metal context
 * @param mode Security level
 * @param signature Output signature buffer
 * @param secret_key Secret key bytes
 * @param message Message to sign
 * @param message_len Message length
 * @param context Optional context string (NULL for empty)
 * @param context_len Context string length
 * @return 0 on success, negative on error
 */
int metal_mldsa_sign(
    MetalMLDSAContext* ctx,
    MLDSAMode mode,
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
 * @param mode Security level
 * @param signatures Output signature buffers (count elements)
 * @param secret_key Secret key bytes
 * @param messages Array of message pointers
 * @param message_lens Array of message lengths
 * @param count Number of messages to sign
 * @return 0 on success, negative on error
 */
int metal_mldsa_batch_sign(
    MetalMLDSAContext* ctx,
    MLDSAMode mode,
    uint8_t** signatures,
    const uint8_t* secret_key,
    const uint8_t* const* messages,
    const size_t* message_lens,
    uint32_t count);

// =============================================================================
// Verification Operations
// =============================================================================

/**
 * Verify an ML-DSA signature on GPU.
 * @param ctx Metal context
 * @param mode Security level
 * @param public_key Public key bytes
 * @param signature Signature bytes
 * @param message Message that was signed
 * @param message_len Message length
 * @param context Optional context string
 * @param context_len Context string length
 * @return 1 if valid, 0 if invalid, negative on error
 */
int metal_mldsa_verify(
    MetalMLDSAContext* ctx,
    MLDSAMode mode,
    const uint8_t* public_key,
    const uint8_t* signature,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* context,
    size_t context_len);

/**
 * Batch verify multiple ML-DSA signatures on GPU.
 * Significantly faster than individual verification for large batches.
 * @param ctx Metal context
 * @param mode Security level
 * @param public_keys Array of public keys
 * @param signatures Array of signatures
 * @param messages Array of message pointers
 * @param message_lens Array of message lengths
 * @param count Number of signatures to verify
 * @param results Output: 1 if valid, 0 if invalid (count elements)
 * @return Number of valid signatures, negative on error
 */
int metal_mldsa_batch_verify(
    MetalMLDSAContext* ctx,
    MLDSAMode mode,
    const uint8_t* const* public_keys,
    const uint8_t* const* signatures,
    const uint8_t* const* messages,
    const size_t* message_lens,
    uint32_t count,
    int* results);

// =============================================================================
// NTT Operations (Low-Level)
// =============================================================================

/**
 * Polynomial representation (256 coefficients mod q).
 */
typedef struct {
    int32_t coeffs[MLDSA_N];
} MLDSAPoly;

/**
 * Batch NTT (Number Theoretic Transform) on GPU.
 * Transforms polynomials to NTT domain.
 * @param ctx Metal context
 * @param out Output polynomials in NTT domain
 * @param in Input polynomials in standard domain
 * @param count Number of polynomials
 * @return 0 on success, negative on error
 */
int metal_mldsa_batch_ntt(
    MetalMLDSAContext* ctx,
    MLDSAPoly* out,
    const MLDSAPoly* in,
    uint32_t count);

/**
 * Batch inverse NTT on GPU.
 * Transforms polynomials from NTT domain to standard.
 * @param ctx Metal context
 * @param out Output polynomials in standard domain
 * @param in Input polynomials in NTT domain
 * @param count Number of polynomials
 * @return 0 on success, negative on error
 */
int metal_mldsa_batch_intt(
    MetalMLDSAContext* ctx,
    MLDSAPoly* out,
    const MLDSAPoly* in,
    uint32_t count);

/**
 * Batch polynomial multiplication in NTT domain.
 * Computes out[i] = a[i] * b[i] (coefficient-wise in NTT domain).
 * @param ctx Metal context
 * @param out Output polynomials
 * @param a First input polynomials (in NTT domain)
 * @param b Second input polynomials (in NTT domain)
 * @param count Number of multiplications
 * @return 0 on success, negative on error
 */
int metal_mldsa_batch_poly_mul(
    MetalMLDSAContext* ctx,
    MLDSAPoly* out,
    const MLDSAPoly* a,
    const MLDSAPoly* b,
    uint32_t count);

// =============================================================================
// Matrix-Vector Operations
// =============================================================================

/**
 * Matrix-vector multiplication on GPU.
 * Computes out = A * v where A is k x l matrix of polynomials.
 * All polynomials must be in NTT domain.
 * @param ctx Metal context
 * @param mode Security level (determines k and l)
 * @param out Output vector (k polynomials)
 * @param matrix Input matrix (k * l polynomials, row-major)
 * @param vector Input vector (l polynomials)
 * @return 0 on success, negative on error
 */
int metal_mldsa_matvec_mul(
    MetalMLDSAContext* ctx,
    MLDSAMode mode,
    MLDSAPoly* out,
    const MLDSAPoly* matrix,
    const MLDSAPoly* vector);

// =============================================================================
// Error Codes
// =============================================================================

#define METAL_MLDSA_SUCCESS           0
#define METAL_MLDSA_ERROR_NO_DEVICE  -1
#define METAL_MLDSA_ERROR_NO_SHADER  -2
#define METAL_MLDSA_ERROR_ALLOC      -3
#define METAL_MLDSA_ERROR_NULL_PTR   -4
#define METAL_MLDSA_ERROR_INVALID    -5
#define METAL_MLDSA_ERROR_VERIFY     -6

#ifdef __cplusplus
}
#endif

#endif // KINET_METAL_MLDSA_H

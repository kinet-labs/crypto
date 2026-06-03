// =============================================================================
// Metal ML-KEM - GPU Acceleration Interface for Post-Quantum Key Encapsulation
// =============================================================================
//
// C++ interface for dispatching ML-KEM (FIPS 203, Module-Lattice Key
// Encapsulation Mechanism) operations to Metal compute shaders.
//
// ML-KEM Parameters:
//   - n = 256 (polynomial degree)
//   - q = 3329 (modulus)
//   - Levels: 512 (128-bit), 768 (192-bit), 1024 (256-bit)
//
// GPU acceleration targets:
//   - NTT/INTT for polynomial multiplication
//   - Matrix-vector products
//   - Batch encapsulation/decapsulation
//
// Copyright (C) 2024-2025 Kinet Industries Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef KINET_METAL_MLKEM_H
#define KINET_METAL_MLKEM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// ML-KEM Constants
// =============================================================================

// Ring parameters
#define MLKEM_N         256     // Polynomial degree
#define MLKEM_Q         3329    // Modulus q
#define MLKEM_Q_BITS    12      // log2(q) rounded up

// Shared key size (all modes)
#define MLKEM_SHARED_KEY_SIZE 32

// ML-KEM-512 (NIST Level 1, 128-bit security)
#define MLKEM512_K               2
#define MLKEM512_PUBLIC_KEY_SIZE 800
#define MLKEM512_SECRET_KEY_SIZE 1632
#define MLKEM512_CIPHERTEXT_SIZE 768

// ML-KEM-768 (NIST Level 3, 192-bit security)
#define MLKEM768_K               3
#define MLKEM768_PUBLIC_KEY_SIZE 1184
#define MLKEM768_SECRET_KEY_SIZE 2400
#define MLKEM768_CIPHERTEXT_SIZE 1088

// ML-KEM-1024 (NIST Level 5, 256-bit security)
#define MLKEM1024_K               4
#define MLKEM1024_PUBLIC_KEY_SIZE 1568
#define MLKEM1024_SECRET_KEY_SIZE 3168
#define MLKEM1024_CIPHERTEXT_SIZE 1568

// =============================================================================
// Context Management
// =============================================================================

/**
 * Opaque handle to Metal ML-KEM compute context.
 */
typedef struct MetalMLKEMContext MetalMLKEMContext;

/**
 * ML-KEM security level.
 */
typedef enum {
    MLKEM_MODE_512  = 0,  // 128-bit security (NIST Level 1)
    MLKEM_MODE_768  = 1,  // 192-bit security (NIST Level 3)
    MLKEM_MODE_1024 = 2,  // 256-bit security (NIST Level 5)
} MLKEMMode;

/**
 * Initialize Metal ML-KEM context.
 * Loads NTT shaders and creates compute pipelines.
 * @return Context handle, or NULL if Metal unavailable
 */
MetalMLKEMContext* metal_mlkem_init(void);

/**
 * Destroy Metal ML-KEM context and release resources.
 */
void metal_mlkem_destroy(MetalMLKEMContext* ctx);

/**
 * Check if Metal acceleration is available for ML-KEM.
 * @return true if Metal GPU is available
 */
bool metal_mlkem_available(void);

// =============================================================================
// Key Generation
// =============================================================================

/**
 * Generate ML-KEM key pair on GPU.
 * Uses GPU-accelerated NTT for matrix expansion.
 * @param ctx Metal context
 * @param mode Security level (512, 768, or 1024)
 * @param public_key Output public key buffer
 * @param secret_key Output secret key buffer
 * @param seed 64-byte random seed (d || z)
 * @return 0 on success, negative on error
 */
int metal_mlkem_keygen(
    MetalMLKEMContext* ctx,
    MLKEMMode mode,
    uint8_t* public_key,
    uint8_t* secret_key,
    const uint8_t* seed);

// =============================================================================
// Encapsulation Operations
// =============================================================================

/**
 * Encapsulate to generate shared secret and ciphertext.
 * @param ctx Metal context
 * @param mode Security level
 * @param ciphertext Output ciphertext buffer
 * @param shared_secret Output 32-byte shared secret
 * @param public_key Recipient's public key
 * @param randomness 32-byte randomness (m)
 * @return 0 on success, negative on error
 */
int metal_mlkem_encaps(
    MetalMLKEMContext* ctx,
    MLKEMMode mode,
    uint8_t* ciphertext,
    uint8_t* shared_secret,
    const uint8_t* public_key,
    const uint8_t* randomness);

/**
 * Batch encapsulation on GPU.
 * Generate multiple shared secrets for different recipients.
 * @param ctx Metal context
 * @param mode Security level
 * @param ciphertexts Output ciphertext buffers (count elements)
 * @param shared_secrets Output shared secrets (count * 32 bytes)
 * @param public_keys Array of recipient public keys
 * @param randomness Random bytes (count * 32 bytes)
 * @param count Number of encapsulations
 * @return 0 on success, negative on error
 */
int metal_mlkem_batch_encaps(
    MetalMLKEMContext* ctx,
    MLKEMMode mode,
    uint8_t** ciphertexts,
    uint8_t* shared_secrets,
    const uint8_t* const* public_keys,
    const uint8_t* randomness,
    uint32_t count);

// =============================================================================
// Decapsulation Operations
// =============================================================================

/**
 * Decapsulate to recover shared secret.
 * @param ctx Metal context
 * @param mode Security level
 * @param shared_secret Output 32-byte shared secret
 * @param ciphertext Input ciphertext
 * @param secret_key Recipient's secret key
 * @return 0 on success, negative on error
 */
int metal_mlkem_decaps(
    MetalMLKEMContext* ctx,
    MLKEMMode mode,
    uint8_t* shared_secret,
    const uint8_t* ciphertext,
    const uint8_t* secret_key);

/**
 * Batch decapsulation on GPU.
 * Recover multiple shared secrets in parallel.
 * @param ctx Metal context
 * @param mode Security level
 * @param shared_secrets Output shared secrets (count * 32 bytes)
 * @param ciphertexts Array of ciphertexts
 * @param secret_key Recipient's secret key (same for all)
 * @param count Number of decapsulations
 * @return 0 on success, negative on error
 */
int metal_mlkem_batch_decaps(
    MetalMLKEMContext* ctx,
    MLKEMMode mode,
    uint8_t* shared_secrets,
    const uint8_t* const* ciphertexts,
    const uint8_t* secret_key,
    uint32_t count);

// =============================================================================
// NTT Operations (Low-Level)
// =============================================================================

/**
 * Polynomial representation (256 coefficients mod q).
 */
typedef struct {
    int16_t coeffs[MLKEM_N];
} MLKEMPoly;

/**
 * Batch NTT (Number Theoretic Transform) on GPU.
 * Transforms polynomials to NTT domain.
 * @param ctx Metal context
 * @param out Output polynomials in NTT domain
 * @param in Input polynomials in standard domain
 * @param count Number of polynomials
 * @return 0 on success, negative on error
 */
int metal_mlkem_batch_ntt(
    MetalMLKEMContext* ctx,
    MLKEMPoly* out,
    const MLKEMPoly* in,
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
int metal_mlkem_batch_intt(
    MetalMLKEMContext* ctx,
    MLKEMPoly* out,
    const MLKEMPoly* in,
    uint32_t count);

/**
 * Batch polynomial multiplication in NTT domain.
 * Uses base-case multiplication for degree-2 polynomials.
 * @param ctx Metal context
 * @param out Output polynomials
 * @param a First input polynomials (in NTT domain)
 * @param b Second input polynomials (in NTT domain)
 * @param count Number of multiplications
 * @return 0 on success, negative on error
 */
int metal_mlkem_batch_poly_mul(
    MetalMLKEMContext* ctx,
    MLKEMPoly* out,
    const MLKEMPoly* a,
    const MLKEMPoly* b,
    uint32_t count);

// =============================================================================
// Matrix-Vector Operations
// =============================================================================

/**
 * Matrix-vector multiplication on GPU.
 * Computes out = A * v where A is k x k matrix of polynomials.
 * All polynomials must be in NTT domain.
 * @param ctx Metal context
 * @param mode Security level (determines k)
 * @param out Output vector (k polynomials)
 * @param matrix Input matrix (k * k polynomials, row-major)
 * @param vector Input vector (k polynomials)
 * @return 0 on success, negative on error
 */
int metal_mlkem_matvec_mul(
    MetalMLKEMContext* ctx,
    MLKEMMode mode,
    MLKEMPoly* out,
    const MLKEMPoly* matrix,
    const MLKEMPoly* vector);

// =============================================================================
// Error Codes
// =============================================================================

#define METAL_MLKEM_SUCCESS           0
#define METAL_MLKEM_ERROR_NO_DEVICE  -1
#define METAL_MLKEM_ERROR_NO_SHADER  -2
#define METAL_MLKEM_ERROR_ALLOC      -3
#define METAL_MLKEM_ERROR_NULL_PTR   -4
#define METAL_MLKEM_ERROR_INVALID    -5

#ifdef __cplusplus
}
#endif

#endif // KINET_METAL_MLKEM_H

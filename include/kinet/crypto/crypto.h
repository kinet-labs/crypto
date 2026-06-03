// =============================================================================
// Kinet Crypto Library - GPU-Accelerated Cryptographic Operations
// =============================================================================
//
// High-performance cryptographic operations with GPU acceleration via MLX.
// This library provides:
// - BLS signatures (BLS12-381) for validator consensus
// - ML-DSA (Dilithium) post-quantum signatures
// - Threshold cryptography operations
// - Hash functions (SHA3, BLAKE3)
//
// Backends:
// - Apple Metal (macOS via MLX)
// - CUDA (Linux/NVIDIA via MLX)
// - Optimized CPU fallback
//

#ifndef KINET_CRYPTO_H
#define KINET_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Library Initialization
// =============================================================================

/**
 * Check if GPU acceleration is available.
 * @return true if GPU (Metal/CUDA) is available
 */
bool crypto_gpu_available(void);

/**
 * Get the name of the active backend.
 * @return "Metal", "CUDA", or "CPU"
 */
const char* crypto_get_backend(void);

/**
 * Clear internal caches.
 */
void crypto_clear_cache(void);

// =============================================================================
// BLS12-381 Signatures
// =============================================================================

// Key sizes
#define BLS_SECRET_KEY_SIZE  32
#define BLS_PUBLIC_KEY_SIZE  48   // G1 point compressed
#define BLS_SIGNATURE_SIZE   96   // G2 point compressed
#define BLS_MESSAGE_SIZE     32   // Hash of message

/**
 * Generate a BLS secret key from random bytes.
 * @param sk Output secret key (32 bytes)
 * @param seed Random seed (NULL for system entropy)
 * @return 0 on success
 */
int bls_keygen(uint8_t* sk, const uint8_t* seed);

/**
 * Derive BLS public key from secret key.
 * @param pk Output public key (48 bytes)
 * @param sk Secret key (32 bytes)
 * @return 0 on success
 */
int bls_sk_to_pk(uint8_t* pk, const uint8_t* sk);

/**
 * Sign a message with BLS.
 * @param sig Output signature (96 bytes)
 * @param sk Secret key (32 bytes)
 * @param msg Message hash (32 bytes)
 * @return 0 on success
 */
int bls_sign(uint8_t* sig, const uint8_t* sk, const uint8_t* msg);

/**
 * Verify a BLS signature.
 * @param sig Signature (96 bytes)
 * @param pk Public key (48 bytes)
 * @param msg Message hash (32 bytes)
 * @return 1 if valid, 0 if invalid
 */
int bls_verify(const uint8_t* sig, const uint8_t* pk, const uint8_t* msg);

/**
 * Aggregate multiple BLS signatures.
 * @param agg_sig Output aggregated signature (96 bytes)
 * @param sigs Array of signatures (each 96 bytes)
 * @param count Number of signatures
 * @return 0 on success
 */
int bls_aggregate_signatures(uint8_t* agg_sig,
                             const uint8_t* const* sigs,
                             uint32_t count);

/**
 * Aggregate multiple BLS public keys.
 * @param agg_pk Output aggregated public key (48 bytes)
 * @param pks Array of public keys (each 48 bytes)
 * @param count Number of public keys
 * @return 0 on success
 */
int bls_aggregate_public_keys(uint8_t* agg_pk,
                              const uint8_t* const* pks,
                              uint32_t count);

/**
 * Verify an aggregated BLS signature against aggregated public key.
 * @param agg_sig Aggregated signature (96 bytes)
 * @param agg_pk Aggregated public key (48 bytes)
 * @param msg Message hash (32 bytes)
 * @return 1 if valid, 0 if invalid
 */
int bls_verify_aggregated(const uint8_t* agg_sig,
                          const uint8_t* agg_pk,
                          const uint8_t* msg);

/**
 * Batch verify multiple BLS signatures (GPU-accelerated).
 * @param sigs Array of signatures (each 96 bytes)
 * @param pks Array of public keys (each 48 bytes)
 * @param msgs Array of message hashes (each 32 bytes)
 * @param count Number of signatures
 * @param results Output array of verification results (1=valid, 0=invalid)
 * @return 0 on success, negative on error
 */
int bls_batch_verify(const uint8_t* const* sigs,
                     const uint8_t* const* pks,
                     const uint8_t* const* msgs,
                     uint32_t count,
                     int* results);

/**
 * Batch sign multiple messages with multiple secret keys (GPU-accelerated).
 * Signs N messages with N secret keys in parallel on GPU.
 * @param sigs Output array of signatures (each 96 bytes, caller allocates)
 * @param sks Array of secret keys (each 32 bytes)
 * @param msgs Array of message hashes (each 32 bytes)
 * @param count Number of signatures to produce
 * @return 0 on success, negative on error
 */
int bls_batch_sign(uint8_t** sigs,
                   const uint8_t* const* sks,
                   const uint8_t* const* msgs,
                   uint32_t count);

// =============================================================================
// ML-DSA (Dilithium) Post-Quantum Signatures
// =============================================================================

// ML-DSA-65 (NIST Level 3) sizes
#define MLDSA_SECRET_KEY_SIZE   4032
#define MLDSA_PUBLIC_KEY_SIZE   1952
#define MLDSA_SIGNATURE_SIZE    3309

/**
 * Generate ML-DSA key pair.
 * @param pk Output public key
 * @param sk Output secret key
 * @param seed Random seed (NULL for system entropy)
 * @return 0 on success
 */
int mldsa_keygen(uint8_t* pk, uint8_t* sk, const uint8_t* seed);

/**
 * Sign a message with ML-DSA.
 * @param sig Output signature
 * @param sig_len Output signature length
 * @param msg Message to sign
 * @param msg_len Message length
 * @param sk Secret key
 * @return 0 on success
 */
int mldsa_sign(uint8_t* sig, size_t* sig_len,
               const uint8_t* msg, size_t msg_len,
               const uint8_t* sk);

/**
 * Verify an ML-DSA signature.
 * @param sig Signature
 * @param sig_len Signature length
 * @param msg Message
 * @param msg_len Message length
 * @param pk Public key
 * @return 1 if valid, 0 if invalid
 */
int mldsa_verify(const uint8_t* sig, size_t sig_len,
                 const uint8_t* msg, size_t msg_len,
                 const uint8_t* pk);

/**
 * Batch verify ML-DSA signatures (GPU-accelerated).
 * Uses NTT acceleration from kinet-labs/lattice.
 * @param sigs Array of signatures
 * @param sig_lens Array of signature lengths
 * @param msgs Array of messages
 * @param msg_lens Array of message lengths
 * @param pks Array of public keys
 * @param count Number of signatures
 * @param results Output verification results
 * @return 0 on success
 */
int mldsa_batch_verify(const uint8_t* const* sigs,
                       const size_t* sig_lens,
                       const uint8_t* const* msgs,
                       const size_t* msg_lens,
                       const uint8_t* const* pks,
                       uint32_t count,
                       int* results);

// =============================================================================
// Threshold Cryptography
// =============================================================================

/**
 * Opaque threshold context.
 */
typedef struct ThresholdContext ThresholdContext;

/**
 * Create a threshold context for t-of-n threshold signatures.
 * @param t Threshold (minimum signers)
 * @param n Total number of signers
 * @return Context handle, or NULL on error
 */
ThresholdContext* threshold_create(uint32_t t, uint32_t n);

/**
 * Free threshold context.
 */
void threshold_destroy(ThresholdContext* ctx);

/**
 * Generate threshold key shares using Shamir Secret Sharing.
 * @param ctx Threshold context
 * @param shares Output array of secret key shares (n shares)
 * @param share_size Size of each share in bytes
 * @param pk Output public key (combined)
 * @param seed Random seed (NULL for system entropy)
 * @return 0 on success
 */
int threshold_keygen(ThresholdContext* ctx,
                     uint8_t** shares,
                     size_t* share_size,
                     uint8_t* pk,
                     const uint8_t* seed);

/**
 * Create a partial signature share.
 * @param ctx Threshold context
 * @param partial_sig Output partial signature
 * @param share_index Index of this signer (0-based)
 * @param share Secret key share
 * @param msg Message hash (32 bytes)
 * @return 0 on success
 */
int threshold_partial_sign(ThresholdContext* ctx,
                           uint8_t* partial_sig,
                           uint32_t share_index,
                           const uint8_t* share,
                           const uint8_t* msg);

/**
 * Combine partial signatures into final signature.
 * Uses Lagrange interpolation (GPU-accelerated).
 * @param ctx Threshold context
 * @param sig Output final signature
 * @param partial_sigs Array of partial signatures
 * @param indices Array of signer indices
 * @param count Number of partial signatures (must be >= t)
 * @return 0 on success
 */
int threshold_combine(ThresholdContext* ctx,
                      uint8_t* sig,
                      const uint8_t* const* partial_sigs,
                      const uint32_t* indices,
                      uint32_t count);

/**
 * Verify a threshold signature.
 * @param ctx Threshold context
 * @param sig Signature
 * @param pk Combined public key
 * @param msg Message hash (32 bytes)
 * @return 1 if valid, 0 if invalid
 */
int threshold_verify(ThresholdContext* ctx,
                     const uint8_t* sig,
                     const uint8_t* pk,
                     const uint8_t* msg);

// =============================================================================
// Hash Functions
// =============================================================================

/**
 * SHA3-256 hash.
 * @param out Output hash (32 bytes)
 * @param in Input data
 * @param len Input length
 */
void crypto_sha3_256(uint8_t* out, const uint8_t* in, size_t len);

/**
 * SHA3-512 hash.
 * @param out Output hash (64 bytes)
 * @param in Input data
 * @param len Input length
 */
void crypto_sha3_512(uint8_t* out, const uint8_t* in, size_t len);

/**
 * BLAKE3 hash.
 * @param out Output hash (32 bytes)
 * @param in Input data
 * @param len Input length
 */
void crypto_blake3(uint8_t* out, const uint8_t* in, size_t len);

/**
 * Batch hash multiple inputs (GPU-accelerated).
 * @param outs Array of output buffers
 * @param ins Array of input buffers
 * @param lens Array of input lengths
 * @param count Number of inputs
 * @param hash_type 0=SHA3-256, 1=SHA3-512, 2=BLAKE3
 * @return 0 on success
 */
int crypto_batch_hash(uint8_t** outs,
                      const uint8_t* const* ins,
                      const size_t* lens,
                      uint32_t count,
                      int hash_type);

// =============================================================================
// Consensus Helpers
// =============================================================================

/**
 * Verify a block's signatures in batch (GPU-accelerated).
 * Combines BLS aggregation verification with threshold verification.
 * @param bls_sigs BLS signatures
 * @param bls_pks BLS public keys
 * @param bls_count Number of BLS signatures
 * @param threshold_sig Threshold signature
 * @param threshold_pk Threshold public key
 * @param block_hash Block hash (32 bytes)
 * @return 1 if all valid, 0 if any invalid
 */
int consensus_verify_block(const uint8_t* const* bls_sigs,
                           const uint8_t* const* bls_pks,
                           uint32_t bls_count,
                           const uint8_t* threshold_sig,
                           const uint8_t* threshold_pk,
                           const uint8_t* block_hash);

// =============================================================================
// Error Codes
// =============================================================================

#define CRYPTO_SUCCESS           0
#define CRYPTO_ERROR_INVALID_KEY -1
#define CRYPTO_ERROR_INVALID_SIG -2
#define CRYPTO_ERROR_NULL_PTR    -3
#define CRYPTO_ERROR_GPU         -4
#define CRYPTO_ERROR_THRESHOLD   -5
#define CRYPTO_ERROR_HASH        -6

#ifdef __cplusplus
}
#endif

#endif // KINET_CRYPTO_H

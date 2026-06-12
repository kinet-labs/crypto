// =============================================================================
// Kinet Crypto - Metal AI Mining Acceleration Header
// =============================================================================
//
// C API for GPU-accelerated AI mining operations:
// - ML-DSA batch signature verification
// - NVTrust attestation verification
// - Reward computation
//
// This header provides the interface used by the Go precompile via cgo.
// Implementation uses Metal (macOS) or CUDA (Linux) backends.
//

#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Context Management
// =============================================================================

/**
 * Opaque Metal AI context for GPU operations.
 * Holds compiled shaders, buffers, and NTT precomputed data.
 */
typedef struct MetalAIContext MetalAIContext;

/**
 * Create a Metal AI context.
 * Initializes GPU device, compiles shaders, precomputes NTT twiddle factors.
 * @return Context handle, or NULL on error
 */
MetalAIContext* metal_ai_create(void);

/**
 * Destroy a Metal AI context and free all GPU resources.
 * @param ctx Context to destroy
 */
void metal_ai_destroy(MetalAIContext* ctx);

/**
 * Check if GPU acceleration is available.
 * @param ctx Context (can be NULL for global check)
 * @return true if Metal/CUDA GPU is available
 */
bool metal_ai_available(MetalAIContext* ctx);

/**
 * Get the GPU backend name.
 * @param ctx Context
 * @return "Metal", "CUDA", or "CPU"
 */
const char* metal_ai_get_backend(MetalAIContext* ctx);

/**
 * Get minimum batch size for GPU acceleration benefit.
 * Below this threshold, CPU may be faster.
 * @param ctx Context
 * @return Minimum batch size (typically 4-8)
 */
int metal_ai_get_threshold(MetalAIContext* ctx);

// =============================================================================
// ML-DSA Batch Verification
// =============================================================================

/**
 * ML-DSA mode constants
 */
#define MLDSA_MODE_44 0x44  // NIST Level 2 (128-bit)
#define MLDSA_MODE_65 0x65  // NIST Level 3 (192-bit)
#define MLDSA_MODE_87 0x87  // NIST Level 5 (256-bit)

/**
 * Batch verify ML-DSA signatures using GPU acceleration.
 * Uses NTT acceleration from kinet-labs/lattice for polynomial operations.
 *
 * @param ctx Metal AI context
 * @param sigs Array of signature pointers
 * @param sig_lens Array of signature lengths
 * @param msgs Array of message pointers
 * @param msg_lens Array of message lengths
 * @param pks Array of public key pointers
 * @param count Number of signatures to verify
 * @param results Output array (1=valid, 0=invalid)
 * @return 0 on success, negative on error
 */
int metal_ai_batch_verify_mldsa(
    MetalAIContext* ctx,
    const uint8_t* const* sigs,
    const size_t* sig_lens,
    const uint8_t* const* msgs,
    const size_t* msg_lens,
    const uint8_t* const* pks,
    uint32_t count,
    int* results
);

/**
 * Single ML-DSA signature verification (convenience wrapper).
 *
 * @param ctx Metal AI context
 * @param sig Signature bytes
 * @param sig_len Signature length
 * @param msg Message bytes
 * @param msg_len Message length
 * @param pk Public key bytes
 * @return 1 if valid, 0 if invalid, negative on error
 */
int metal_ai_verify_mldsa(
    MetalAIContext* ctx,
    const uint8_t* sig,
    size_t sig_len,
    const uint8_t* msg,
    size_t msg_len,
    const uint8_t* pk
);

// =============================================================================
// NVTrust Attestation Verification
// =============================================================================

/**
 * Attestation result structure
 */
typedef struct {
    bool valid;           // Overall verification result
    uint8_t trust_score;  // Trust score (0-100)
    bool hardware_cc;     // Hardware confidential computing enabled
    bool rim_verified;    // Reference Integrity Manifest verified
    uint8_t mode;         // 0=Local, 1=Software
} MetalAIAttestResult;

/**
 * Batch verify NVTrust attestations using GPU acceleration.
 *
 * @param ctx Metal AI context
 * @param quotes Array of quote data pointers
 * @param quote_lens Array of quote lengths
 * @param count Number of quotes to verify
 * @param results Output array of attestation results
 * @return 0 on success, negative on error
 */
int metal_ai_batch_verify_attestation(
    MetalAIContext* ctx,
    const uint8_t* const* quotes,
    const size_t* quote_lens,
    uint32_t count,
    MetalAIAttestResult* results
);

/**
 * Single attestation verification (convenience wrapper).
 *
 * @param ctx Metal AI context
 * @param quote Quote data
 * @param quote_len Quote length
 * @param result Output attestation result
 * @return 0 on success, negative on error
 */
int metal_ai_verify_attestation(
    MetalAIContext* ctx,
    const uint8_t* quote,
    size_t quote_len,
    MetalAIAttestResult* result
);

// =============================================================================
// Reward Computation
// =============================================================================

/**
 * Work proof structure for reward calculation
 */
typedef struct {
    uint8_t device_id[32];   // GPU/Device identifier
    uint8_t nonce[32];       // Random nonce
    uint64_t timestamp;      // Unix timestamp
    uint16_t privacy_level;  // 1=Public, 2=Private, 3=Confidential, 4=Sovereign
    uint32_t compute_mins;   // Compute minutes
    const uint8_t* tee_quote; // Optional TEE quote
    size_t tee_quote_len;    // TEE quote length
} MetalAIWorkProof;

/**
 * Batch compute rewards using GPU acceleration.
 *
 * @param ctx Metal AI context
 * @param proofs Array of work proofs
 * @param count Number of work proofs
 * @param chain_id Chain ID for chain-specific adjustments
 * @param rewards Output array (32 bytes each, big-endian)
 * @return 0 on success, negative on error
 */
int metal_ai_batch_compute_reward(
    MetalAIContext* ctx,
    const MetalAIWorkProof* proofs,
    uint32_t count,
    uint64_t chain_id,
    uint8_t (*rewards)[32]
);

/**
 * Single reward computation (convenience wrapper).
 *
 * @param ctx Metal AI context
 * @param proof Work proof
 * @param chain_id Chain ID
 * @param reward Output reward (32 bytes, big-endian)
 * @return 0 on success, negative on error
 */
int metal_ai_compute_reward(
    MetalAIContext* ctx,
    const MetalAIWorkProof* proof,
    uint64_t chain_id,
    uint8_t reward[32]
);

// =============================================================================
// NTT Operations (for advanced users)
// =============================================================================

/**
 * Perform forward NTT on a batch of polynomials.
 * Uses ML-DSA parameters (n=256, q=8380417).
 *
 * @param ctx Metal AI context
 * @param data Array of polynomial coefficient arrays (modified in-place)
 * @param count Number of polynomials
 * @return 0 on success, negative on error
 */
int metal_ai_ntt_forward(
    MetalAIContext* ctx,
    uint32_t** data,
    uint32_t count
);

/**
 * Perform inverse NTT on a batch of polynomials.
 *
 * @param ctx Metal AI context
 * @param data Array of polynomial coefficient arrays (modified in-place)
 * @param count Number of polynomials
 * @return 0 on success, negative on error
 */
int metal_ai_ntt_inverse(
    MetalAIContext* ctx,
    uint32_t** data,
    uint32_t count
);

// =============================================================================
// Statistics and Debugging
// =============================================================================

/**
 * GPU statistics structure
 */
typedef struct {
    uint64_t batch_verifications;  // Number of batch verification calls
    uint64_t total_signatures;     // Total signatures verified
    uint64_t gpu_time_ns;          // Total GPU time in nanoseconds
    uint64_t cpu_fallbacks;        // Number of CPU fallback operations
} MetalAIStats;

/**
 * Get GPU statistics.
 *
 * @param ctx Metal AI context
 * @param stats Output statistics
 */
void metal_ai_get_stats(MetalAIContext* ctx, MetalAIStats* stats);

/**
 * Reset GPU statistics.
 *
 * @param ctx Metal AI context
 */
void metal_ai_reset_stats(MetalAIContext* ctx);

// =============================================================================
// Error Codes
// =============================================================================

#define METAL_AI_SUCCESS           0
#define METAL_AI_ERROR_NO_GPU     -1
#define METAL_AI_ERROR_NO_CONTEXT -2
#define METAL_AI_ERROR_INVALID_SIG -3
#define METAL_AI_ERROR_INVALID_PK -4
#define METAL_AI_ERROR_NTT        -5
#define METAL_AI_ERROR_MEMORY     -6
#define METAL_AI_ERROR_ATTESTATION -7

#ifdef __cplusplus
}
#endif

// =============================================================================
// Metal Lamport - GPU Acceleration for Lamport One-Time Signatures
// =============================================================================
//
// Hash-based post-quantum signatures. Simple, fast, quantum-resistant.
// GPU acceleration for batch key generation and verification.
//

#ifndef KINET_METAL_LAMPORT_H
#define KINET_METAL_LAMPORT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Context Management
// =============================================================================

typedef struct MetalLamportContext MetalLamportContext;

MetalLamportContext* metal_lamport_init(void);
void metal_lamport_destroy(MetalLamportContext* ctx);
bool metal_lamport_available(void);

// =============================================================================
// Hash Function Selection
// =============================================================================

typedef enum {
    LAMPORT_SHA256 = 0,
    LAMPORT_SHA512 = 1,
    LAMPORT_SHA3_256 = 2,
    LAMPORT_SHA3_512 = 3,
    LAMPORT_BLAKE3 = 4,
} LamportHashFunc;

// =============================================================================
// Key Sizes (SHA-256)
// =============================================================================

#define LAMPORT_SHA256_HASH_SIZE    32
#define LAMPORT_SHA256_PRIVKEY_SIZE (256 * 2 * 32)  // 16 KB
#define LAMPORT_SHA256_PUBKEY_SIZE  (256 * 2 * 32)  // 16 KB
#define LAMPORT_SHA256_SIG_SIZE     (256 * 32)      // 8 KB

// =============================================================================
// Return Codes
// =============================================================================

typedef enum {
    METAL_LAMPORT_SUCCESS = 0,
    METAL_LAMPORT_ERROR_INIT = -1,
    METAL_LAMPORT_ERROR_INVALID_INPUT = -2,
    METAL_LAMPORT_ERROR_GPU_DISPATCH = -3,
    METAL_LAMPORT_ERROR_VERIFY_FAILED = -4,
} MetalLamportResult;

// =============================================================================
// Key Generation
// =============================================================================

/**
 * Generate Lamport key pair.
 * Private key: 512 random values (256 pairs for 0/1 bits)
 * Public key: Hash of each private key value
 *
 * @param ctx       Metal context
 * @param hash_func Hash function to use
 * @param privkey   Output private key buffer
 * @param pubkey    Output public key buffer
 * @param seed      32-byte seed (NULL for random)
 */
MetalLamportResult metal_lamport_keygen(
    MetalLamportContext* ctx,
    LamportHashFunc hash_func,
    uint8_t* privkey,
    uint8_t* pubkey,
    const uint8_t* seed
);

/**
 * Batch key generation - generate multiple key pairs in parallel.
 * Highly efficient on GPU due to independent hash computations.
 *
 * @param ctx       Metal context
 * @param hash_func Hash function
 * @param privkeys  Output private keys array
 * @param pubkeys   Output public keys array
 * @param seeds     Seeds array (NULL for random)
 * @param count     Number of key pairs to generate
 */
MetalLamportResult metal_lamport_batch_keygen(
    MetalLamportContext* ctx,
    LamportHashFunc hash_func,
    uint8_t* privkeys,
    uint8_t* pubkeys,
    const uint8_t* seeds,
    uint32_t count
);

// =============================================================================
// Signing
// =============================================================================

/**
 * Sign a message hash with Lamport signature.
 * WARNING: Each private key must only be used ONCE!
 *
 * @param ctx           Metal context
 * @param hash_func     Hash function
 * @param signature     Output signature
 * @param privkey       Private key (consumed - should be deleted after use)
 * @param message_hash  32-byte hash of message to sign
 */
MetalLamportResult metal_lamport_sign(
    MetalLamportContext* ctx,
    LamportHashFunc hash_func,
    uint8_t* signature,
    const uint8_t* privkey,
    const uint8_t* message_hash
);

/**
 * Batch signing - sign multiple messages with different keys.
 */
MetalLamportResult metal_lamport_batch_sign(
    MetalLamportContext* ctx,
    LamportHashFunc hash_func,
    uint8_t* signatures,
    const uint8_t* privkeys,
    const uint8_t* message_hashes,
    uint32_t count
);

// =============================================================================
// Verification
// =============================================================================

/**
 * Verify a Lamport signature.
 *
 * @param ctx           Metal context
 * @param hash_func     Hash function
 * @param pubkey        Public key
 * @param signature     Signature to verify
 * @param message_hash  Hash of original message
 * @return METAL_LAMPORT_SUCCESS if valid
 */
MetalLamportResult metal_lamport_verify(
    MetalLamportContext* ctx,
    LamportHashFunc hash_func,
    const uint8_t* pubkey,
    const uint8_t* signature,
    const uint8_t* message_hash
);

/**
 * Batch verification - verify multiple signatures in parallel.
 * Very efficient on GPU - each verification is independent.
 *
 * @param ctx           Metal context
 * @param hash_func     Hash function
 * @param pubkeys       Array of public keys
 * @param signatures    Array of signatures
 * @param message_hashes Array of message hashes
 * @param count         Number of signatures to verify
 * @param results       Output array of verification results
 */
MetalLamportResult metal_lamport_batch_verify(
    MetalLamportContext* ctx,
    LamportHashFunc hash_func,
    const uint8_t* pubkeys,
    const uint8_t* signatures,
    const uint8_t* message_hashes,
    uint32_t count,
    bool* results
);

// =============================================================================
// Winternitz OTS (WOTS) - Compact Variant
// =============================================================================
// WOTS reduces signature size by using hash chains.
// Trade-off: Smaller signatures but more hash computations.

#define WOTS_W4_SIG_SIZE   (67 * 32)   // w=4: ~2 KB signatures
#define WOTS_W16_SIG_SIZE  (35 * 32)   // w=16: ~1 KB signatures

/**
 * Generate WOTS key pair (more compact than Lamport).
 *
 * @param ctx       Metal context
 * @param hash_func Hash function
 * @param w         Winternitz parameter (4 or 16)
 * @param privkey   Output private key
 * @param pubkey    Output public key
 * @param seed      Seed (NULL for random)
 */
MetalLamportResult metal_wots_keygen(
    MetalLamportContext* ctx,
    LamportHashFunc hash_func,
    uint8_t w,
    uint8_t* privkey,
    uint8_t* pubkey,
    const uint8_t* seed
);

MetalLamportResult metal_wots_sign(
    MetalLamportContext* ctx,
    LamportHashFunc hash_func,
    uint8_t w,
    uint8_t* signature,
    const uint8_t* privkey,
    const uint8_t* message_hash
);

MetalLamportResult metal_wots_verify(
    MetalLamportContext* ctx,
    LamportHashFunc hash_func,
    uint8_t w,
    const uint8_t* pubkey,
    const uint8_t* signature,
    const uint8_t* message_hash
);

#ifdef __cplusplus
}
#endif

#endif // KINET_METAL_LAMPORT_H

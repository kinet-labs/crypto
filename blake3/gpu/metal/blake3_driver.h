// =============================================================================
// Metal BLAKE3 - GPU Acceleration for BLAKE3 Hash
// =============================================================================
//
// High-performance BLAKE3 hashing with GPU parallelization.
// Based on the official BLAKE3 specification.
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

typedef struct MetalBLAKE3Context MetalBLAKE3Context;

MetalBLAKE3Context* metal_blake3_init(void);
void metal_blake3_destroy(MetalBLAKE3Context* ctx);
bool metal_blake3_available(void);

// =============================================================================
// Constants
// =============================================================================

#define BLAKE3_OUT_LEN      32
#define BLAKE3_KEY_LEN      32
#define BLAKE3_BLOCK_LEN    64
#define BLAKE3_CHUNK_LEN    1024

// =============================================================================
// Return Codes
// =============================================================================

typedef enum {
    METAL_BLAKE3_SUCCESS = 0,
    METAL_BLAKE3_ERROR_INIT = -1,
    METAL_BLAKE3_ERROR_INVALID_INPUT = -2,
    METAL_BLAKE3_ERROR_GPU_DISPATCH = -3,
} MetalBLAKE3Result;

// =============================================================================
// Simple Hash Interface
// =============================================================================

/**
 * Hash data with BLAKE3.
 *
 * @param ctx       Metal context
 * @param output    Output hash (32 bytes or more for XOF)
 * @param out_len   Output length (32 for standard, more for XOF)
 * @param input     Input data
 * @param in_len    Input length
 */
MetalBLAKE3Result metal_blake3_hash(
    MetalBLAKE3Context* ctx,
    uint8_t* output,
    size_t out_len,
    const uint8_t* input,
    size_t in_len
);

/**
 * Batch hash - hash multiple inputs in parallel.
 * Highly efficient for many small inputs.
 *
 * @param ctx       Metal context
 * @param outputs   Output hashes (32 bytes each)
 * @param inputs    Array of input pointers
 * @param in_lens   Array of input lengths
 * @param count     Number of inputs
 */
MetalBLAKE3Result metal_blake3_batch_hash(
    MetalBLAKE3Context* ctx,
    uint8_t* outputs,
    const uint8_t** inputs,
    const size_t* in_lens,
    uint32_t count
);

/**
 * Batch hash fixed-size inputs (optimized path).
 * All inputs must be the same size.
 *
 * @param ctx       Metal context
 * @param outputs   Output hashes
 * @param inputs    Contiguous input data
 * @param in_len    Size of each input
 * @param count     Number of inputs
 */
MetalBLAKE3Result metal_blake3_batch_hash_fixed(
    MetalBLAKE3Context* ctx,
    uint8_t* outputs,
    const uint8_t* inputs,
    size_t in_len,
    uint32_t count
);

// =============================================================================
// Keyed Hash (MAC)
// =============================================================================

/**
 * Keyed BLAKE3 hash (for MAC).
 *
 * @param ctx       Metal context
 * @param output    Output MAC
 * @param out_len   Output length
 * @param key       32-byte key
 * @param input     Input data
 * @param in_len    Input length
 */
MetalBLAKE3Result metal_blake3_keyed_hash(
    MetalBLAKE3Context* ctx,
    uint8_t* output,
    size_t out_len,
    const uint8_t key[BLAKE3_KEY_LEN],
    const uint8_t* input,
    size_t in_len
);

/**
 * Batch keyed hash with same key.
 */
MetalBLAKE3Result metal_blake3_batch_keyed_hash(
    MetalBLAKE3Context* ctx,
    uint8_t* outputs,
    const uint8_t key[BLAKE3_KEY_LEN],
    const uint8_t** inputs,
    const size_t* in_lens,
    uint32_t count
);

// =============================================================================
// Key Derivation (KDF)
// =============================================================================

/**
 * Derive key using BLAKE3 KDF.
 *
 * @param ctx           Metal context
 * @param output        Output key material
 * @param out_len       Output length
 * @param context       Context string
 * @param context_len   Context string length
 * @param key_material  Input key material
 * @param km_len        Key material length
 */
MetalBLAKE3Result metal_blake3_derive_key(
    MetalBLAKE3Context* ctx,
    uint8_t* output,
    size_t out_len,
    const char* context,
    size_t context_len,
    const uint8_t* key_material,
    size_t km_len
);

// =============================================================================
// Streaming Interface (Incremental Hashing)
// =============================================================================

typedef struct MetalBLAKE3Hasher MetalBLAKE3Hasher;

/**
 * Create new BLAKE3 hasher.
 */
MetalBLAKE3Hasher* metal_blake3_hasher_new(MetalBLAKE3Context* ctx);

/**
 * Create keyed hasher.
 */
MetalBLAKE3Hasher* metal_blake3_hasher_new_keyed(
    MetalBLAKE3Context* ctx,
    const uint8_t key[BLAKE3_KEY_LEN]
);

/**
 * Create KDF hasher.
 */
MetalBLAKE3Hasher* metal_blake3_hasher_new_derive_key(
    MetalBLAKE3Context* ctx,
    const char* context,
    size_t context_len
);

/**
 * Update hasher with more data.
 */
MetalBLAKE3Result metal_blake3_hasher_update(
    MetalBLAKE3Hasher* hasher,
    const uint8_t* input,
    size_t in_len
);

/**
 * Finalize and get output.
 */
MetalBLAKE3Result metal_blake3_hasher_finalize(
    MetalBLAKE3Hasher* hasher,
    uint8_t* output,
    size_t out_len
);

/**
 * Reset hasher for reuse.
 */
void metal_blake3_hasher_reset(MetalBLAKE3Hasher* hasher);

/**
 * Free hasher.
 */
void metal_blake3_hasher_free(MetalBLAKE3Hasher* hasher);

// =============================================================================
// Merkle Tree (BLAKE3-native parallelism)
// =============================================================================

/**
 * Compute BLAKE3 Merkle tree root.
 * Uses BLAKE3's native tree hashing mode.
 *
 * @param ctx       Metal context
 * @param root      Output root (32 bytes)
 * @param leaves    Leaf data (each 32 bytes)
 * @param count     Number of leaves (power of 2)
 */
MetalBLAKE3Result metal_blake3_merkle_root(
    MetalBLAKE3Context* ctx,
    uint8_t root[BLAKE3_OUT_LEN],
    const uint8_t* leaves,
    uint32_t count
);

/**
 * Build full BLAKE3 Merkle tree.
 */
MetalBLAKE3Result metal_blake3_merkle_tree(
    MetalBLAKE3Context* ctx,
    uint8_t* nodes,
    const uint8_t* leaves,
    uint32_t count
);

// =============================================================================
// Large File Hashing (Streaming with GPU chunks)
// =============================================================================

/**
 * Hash large file with GPU-accelerated chunk processing.
 * Processes 1MB chunks in parallel on GPU.
 *
 * @param ctx       Metal context
 * @param output    Output hash
 * @param out_len   Output length
 * @param path      File path
 */
MetalBLAKE3Result metal_blake3_hash_file(
    MetalBLAKE3Context* ctx,
    uint8_t* output,
    size_t out_len,
    const char* path
);

#ifdef __cplusplus
}
#endif

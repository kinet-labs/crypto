// Public C ABI for the CUDA AEAD batch driver. The driver compiles in two
// modes:
//   * KINET_AEAD_HAVE_CUDA defined  -> real CUDA dispatch
//   * not defined                 -> stub mode, every entry returns -1
//
// All entry points return 0 on success, negative on failure (matching the
// Metal driver convention in gpu/metal/*_driver.mm).

#pragma once

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// Returns 1 if a CUDA-capable device is reachable, 0 otherwise.
int kinet_aead_cuda_available(void);

// Encrypt n ChaCha20-Poly1305 messages in a single GPU dispatch.
//
//   keys             -- n * 32 bytes (ChaCha20 keys)
//   nonces           -- n * 12 bytes (RFC 8439 IETF nonces)
//   inputs_arena     -- packed (aad || plaintext) per message
//   inputs_arena_len -- total bytes of inputs_arena (may be 0)
//   jobs             -- n AeadJob records (32 bytes each, see *.cu structs)
//   n                -- number of messages
//   outputs_arena    -- caller-allocated; receives (ciphertext || 16-byte tag)
//   outputs_arena_len-- total capacity of outputs_arena
//
// Returns 0 on success.
int aead_chacha20poly1305_batch_cuda(
    const uint8_t* keys,
    const uint8_t* nonces,
    const uint8_t* inputs_arena,
    size_t         inputs_arena_len,
    const void*    jobs,
    size_t         n,
    uint8_t*       outputs_arena,
    size_t         outputs_arena_len);

// Encrypt n AES-256-GCM messages in a single GPU dispatch.
// Layout matches aead_chacha20poly1305_batch_cuda; nonces[] holds 12-byte
// IVs (NIST SP 800-38D 96-bit IV path).
int aead_aes_256_gcm_batch_cuda(
    const uint8_t* keys,
    const uint8_t* ivs,
    const uint8_t* inputs_arena,
    size_t         inputs_arena_len,
    const void*    jobs,
    size_t         n,
    uint8_t*       outputs_arena,
    size_t         outputs_arena_len);

#ifdef __cplusplus
}  // extern "C"
#endif

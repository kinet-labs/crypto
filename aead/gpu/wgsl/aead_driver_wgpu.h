// Public C ABI for the WebGPU/WGSL batched AEAD driver. The driver
// compiles in two modes:
//   * KINET_AEAD_HAS_WEBGPU defined  -> real wgpu-native dispatch
//   * not defined                  -> stub mode, every entry returns -1
//
// All entry points return 0 on success, negative on failure (matching
// the Metal and CUDA driver conventions).

#pragma once

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

int kinet_aead_wgpu_available(void);

int aead_chacha20poly1305_batch_wgpu(
    const uint8_t* keys,
    const uint8_t* nonces,
    const uint8_t* inputs_arena,
    size_t         inputs_arena_len,
    const void*    jobs,
    size_t         n,
    uint8_t*       outputs_arena,
    size_t         outputs_arena_len);

int aead_aes_256_gcm_batch_wgpu(
    const uint8_t* keys,
    const uint8_t* ivs,
    const uint8_t* inputs_arena,
    size_t         inputs_arena_len,
    const void*    jobs,
    size_t         n,
    uint8_t*       outputs_arena,
    size_t         outputs_arena_len);

#ifdef __cplusplus
}
#endif

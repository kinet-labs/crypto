// Public C-ABI for the SHA-256 WebGPU/WGSL driver. On hosts without a wgpu
// runtime, kinet_sha256_wgpu_available() returns 0 and sha256_batch_wgpu()
// returns -1.

#ifndef KINET_SHA256_DRIVER_WGPU_H
#define KINET_SHA256_DRIVER_WGPU_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Returns 1 if a WebGPU adapter+device initialised successfully, 0 otherwise.
int kinet_sha256_wgpu_available(void);

// Run N SHA-256 hashes in one WGSL dispatch. Inputs share a flat byte arena;
// outputs are written as 32 contiguous bytes per hash. Returns 0 on success,
// negative on failure.
int sha256_batch_wgpu(
    const uint8_t*  inputs_arena,
    size_t          inputs_arena_len,
    const uint32_t* input_offsets,
    const uint32_t* input_lens,
    size_t          n,
    uint8_t*        outputs_arena);

#ifdef __cplusplus
}
#endif

#endif // KINET_SHA256_DRIVER_WGPU_H

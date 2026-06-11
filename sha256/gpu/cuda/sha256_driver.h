// Public C-ABI interface for the SHA-256 CUDA driver. Mirrors the Metal
// driver in sha256/gpu/metal/sha256_batch_driver.mm. On hosts without CUDA
// every function returns -1 except kinet_sha256_cuda_available() which
// returns 0.

#ifndef KINET_SHA256_DRIVER_CUDA_H
#define KINET_SHA256_DRIVER_CUDA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Returns 1 if a CUDA device is available, 0 otherwise.
int kinet_sha256_cuda_available(void);

// Run N SHA-256 hashes in one CUDA dispatch. Each input lives at
// inputs_arena[input_offsets[i] .. + input_lens[i]); each output goes to
// outputs_arena[i * 32 .. i * 32 + 32). Inputs are concatenated in
// `inputs_arena` of length `inputs_arena_len`. Returns 0 on success,
// negative on failure (-1 = invalid args, -2 = device unavailable,
// -3 = device alloc failed, -4 = launch failed).
int sha256_batch_cuda(
    const uint8_t*  inputs_arena,
    size_t          inputs_arena_len,
    const uint32_t* input_offsets,
    const uint32_t* input_lens,
    size_t          n,
    uint8_t*        outputs_arena);

#ifdef __cplusplus
}
#endif

#endif // KINET_SHA256_DRIVER_CUDA_H

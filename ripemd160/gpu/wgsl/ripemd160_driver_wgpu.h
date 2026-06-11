// Public C-ABI for the RIPEMD-160 WebGPU/WGSL driver. On hosts without a
// wgpu runtime, kinet_ripemd160_wgpu_available() returns 0 and
// ripemd160_batch_wgpu() returns -1.

#ifndef KINET_RIPEMD160_DRIVER_WGPU_H
#define KINET_RIPEMD160_DRIVER_WGPU_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Returns 1 if a WebGPU adapter+device initialised successfully, 0 otherwise.
int kinet_ripemd160_wgpu_available(void);

// Run N RIPEMD-160 hashes in one WGSL dispatch. Inputs share a flat byte
// arena; outputs are written as 20 contiguous bytes per hash. Returns 0 on
// success, negative on failure.
int ripemd160_batch_wgpu(
    const uint8_t*  inputs_arena,
    size_t          inputs_arena_len,
    const uint32_t* input_offsets,
    const uint32_t* input_lens,
    size_t          n,
    uint8_t*        outputs_arena);

#ifdef __cplusplus
}
#endif

#endif // KINET_RIPEMD160_DRIVER_WGPU_H

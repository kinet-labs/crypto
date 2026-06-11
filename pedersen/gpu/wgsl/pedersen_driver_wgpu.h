// Public C-ABI for the WebGPU/WGSL driver of the batched Pedersen vector
// commitment.  Mirrors pedersen_batch_metal exactly.

#ifndef KINET_PEDERSEN_DRIVER_WGPU_H
#define KINET_PEDERSEN_DRIVER_WGPU_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

int kinet_pedersen_wgpu_available(void);

int pedersen_batch_wgpu(
    const uint8_t* gens_be,
    const uint8_t* scalars_be,
    const uint8_t* blindings_be,
    uint32_t       M,
    uint32_t       N,
    uint8_t*       out_be);

#ifdef __cplusplus
}
#endif

#endif // KINET_PEDERSEN_DRIVER_WGPU_H

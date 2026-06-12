// Tree-reduce WebGPU/WGSL driver for the batched Pedersen vector commitment
// at the fixed Verkle width N = 256.

#ifndef KINET_PEDERSEN_TREE_DRIVER_WGPU_H
#define KINET_PEDERSEN_TREE_DRIVER_WGPU_H

#include <cstdint>

#ifndef PEDERSEN_TREE_WIDTH
#define PEDERSEN_TREE_WIDTH 256u
#endif

#ifdef __cplusplus
extern "C" {
#endif

int kinet_pedersen_tree_wgpu_available(void);

int pedersen_tree_wgpu(
    const uint8_t* gens_be,
    const uint8_t* scalars_be,
    const uint8_t* blindings_be,
    uint32_t       M,
    uint8_t*       out_be);

#ifdef __cplusplus
}
#endif

#endif // KINET_PEDERSEN_TREE_DRIVER_WGPU_H

// Tree-reduce CUDA driver for the batched Pedersen vector commitment at the
// fixed Verkle width N = 256.

#ifndef KINET_PEDERSEN_TREE_DRIVER_CUDA_H
#define KINET_PEDERSEN_TREE_DRIVER_CUDA_H

#include <cstdint>

#ifndef PEDERSEN_TREE_WIDTH
#define PEDERSEN_TREE_WIDTH 256u
#endif

#ifdef __cplusplus
extern "C" {
#endif

int kinet_pedersen_tree_cuda_available(void);

// Computes M Pedersen commitments at the fixed width N = 256 in a single
// CUDA dispatch with block-shared-memory tree reduction. Wire format
// identical to pedersen_batch_cuda.
int pedersen_tree_cuda(
    const uint8_t* gens_be,
    const uint8_t* scalars_be,
    const uint8_t* blindings_be,
    uint32_t       M,
    uint8_t*       out_be);

#ifdef __cplusplus
}
#endif

#endif // KINET_PEDERSEN_TREE_DRIVER_CUDA_H

// CUDA driver for Banderwagon group ops. Linux/CUDA on real GPUs; host-side
// polyfill when nvcc is unavailable so the CPU oracle test path stays
// exercised. Same encoding as the Metal driver.

#ifndef KINET_BANDERWAGON_CUDA_DRIVER_H
#define KINET_BANDERWAGON_CUDA_DRIVER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int banderwagon_cuda_add_batch(const uint8_t *pairs,
                               uint8_t       *outs,
                               unsigned long  n);

int banderwagon_cuda_double_batch(const uint8_t *pts,
                                  uint8_t       *outs,
                                  unsigned long  n);

int banderwagon_cuda_smul_batch(const uint8_t *pts,
                                const uint8_t *scalars,
                                uint8_t       *outs,
                                unsigned long  n);

int banderwagon_cuda_msm_batch(const uint8_t *pts,
                               const uint8_t *scalars,
                               uint8_t       *outs,
                               unsigned long  n,
                               unsigned long  M);

#ifdef __cplusplus
}
#endif

#endif

// WGSL driver for Banderwagon group ops. Runs the algorithm via a C++ host
// polyfill that emulates the kernel's u32-only arithmetic (WGSL has no native
// u64). Same encoding as the Metal/CUDA drivers: 96-byte Pt, 32-byte LE Fr.

#ifndef KINET_BANDERWAGON_WGSL_DRIVER_H
#define KINET_BANDERWAGON_WGSL_DRIVER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int banderwagon_wgsl_add_batch(const uint8_t *pairs,
                               uint8_t       *outs,
                               unsigned long  n);

int banderwagon_wgsl_double_batch(const uint8_t *pts,
                                  uint8_t       *outs,
                                  unsigned long  n);

int banderwagon_wgsl_smul_batch(const uint8_t *pts,
                                const uint8_t *scalars,
                                uint8_t       *outs,
                                unsigned long  n);

int banderwagon_wgsl_msm_batch(const uint8_t *pts,
                               const uint8_t *scalars,
                               uint8_t       *outs,
                               unsigned long  n,
                               unsigned long  M);

#ifdef __cplusplus
}
#endif

#endif

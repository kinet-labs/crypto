// WGSL driver for the multi-curve Pippenger MSM kernel.
// v1.1 NOTIMPL; the kernel source ships in multi_pippenger.wgsl.

#include "kinet/gpukit/multi_pippenger.h"
#include "kinet/gpukit/gpukit.h"

extern "C" int gpukit_multi_pippenger_wgsl(uint32_t /*curve*/,
                                           const uint8_t* /*scalars*/,
                                           const uint8_t* /*points*/,
                                           size_t /*n*/,
                                           uint8_t* /*result*/) {
    return GPUKIT_ERR_NOTIMPL;
}

// Metal driver for the multi-curve Pippenger MSM kernel.
//
// v1.1 ships the CPU reference (gpukit_multi_pippenger_cpu) and the kernel
// source files in gpu/metal/multi_pippenger_*.metal. Cross-curve byte-equal
// validation against the CPU oracle is scheduled for v1.2; until then the
// driver returns NOTIMPL honestly so the caller can fall back to CPU.
//
// Wiring the dispatch path is pinned by the kernel skeleton in
// multi_pippenger.metal: the bucket-sort + reduction live in a curve-agnostic
// kernel that #includes <curve_traits/<curve>_traits.h.metal>; one metallib
// entry point per curve is exposed.

#if __APPLE__ && __OBJC__

#include "kinet/gpukit/multi_pippenger.h"
#include "kinet/gpukit/gpukit.h"

extern "C" int gpukit_multi_pippenger_metal(uint32_t curve,
                                            const uint8_t* /*scalars*/,
                                            const uint8_t* /*points*/,
                                            size_t /*n*/,
                                            uint8_t* /*result*/) {
    (void)curve;
    return GPUKIT_ERR_NOTIMPL;
}

#endif  // __APPLE__ && __OBJC__

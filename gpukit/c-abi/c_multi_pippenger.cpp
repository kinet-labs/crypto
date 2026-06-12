// C-ABI top-level dispatcher for the multi-curve Pippenger MSM kernel.
// Routes to the active gpukit backend (cpu / metal / cuda / wgsl) and falls
// back to CPU on NOTIMPL or backend errors. The unified entry point matches
// the spec in include/kinet/gpukit/multi_pippenger.h.

#include "kinet/gpukit/multi_pippenger.h"
#include "kinet/gpukit/gpukit.h"

extern "C" int gpukit_multi_pippenger(uint32_t curve,
                                      const uint8_t* scalars,
                                      const uint8_t* points,
                                      size_t n,
                                      uint8_t* result) {
    if (!result) return GPUKIT_ERR_NULL_ARG;
    if (n > 0 && (!scalars || !points)) return GPUKIT_ERR_NULL_ARG;

    const gpukit_backend backend = gpukit_active_backend();
    int rc = GPUKIT_ERR_NOTIMPL;

    switch (backend) {
        case GPUKIT_BACKEND_METAL:
            rc = gpukit_multi_pippenger_metal(curve, scalars, points, n, result);
            break;
        case GPUKIT_BACKEND_CUDA:
            rc = gpukit_multi_pippenger_cuda(curve, scalars, points, n, result);
            break;
        case GPUKIT_BACKEND_WGSL:
            rc = gpukit_multi_pippenger_wgsl(curve, scalars, points, n, result);
            break;
        case GPUKIT_BACKEND_CPU:
        default:
            rc = gpukit_multi_pippenger_cpu(curve, scalars, points, n, result);
            return rc;
    }

    // GPU backend missed or hit NOTIMPL -- fall back to CPU.
    if (rc == GPUKIT_ERR_NOTIMPL || rc == GPUKIT_ERR_BACKEND) {
        rc = gpukit_multi_pippenger_cpu(curve, scalars, points, n, result);
    }
    return rc;
}

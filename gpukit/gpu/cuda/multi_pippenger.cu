// CUDA kernel for the multi-curve Pippenger MSM.
//
// Unlike Metal, CUDA supports template instantiation across translation
// units. The shared bucket-sort + reduction skeleton is templated over a
// CurveTrait struct that supplies the field arithmetic and group ops; one
// extern-template instance per supported curve is exposed to the host driver.
//
// v1.1 ships the entry-point signatures. Body filling (including the
// threadgroup reduction tree for bucket aggregation) is scheduled for v1.2,
// alongside the Metal validation work. The driver returns NOTIMPL until
// then; the C-ABI multi_pippenger entry routes to the CPU body.

#include "kinet/gpukit/multi_pippenger.h"
#include "kinet/gpukit/gpukit.h"

#ifdef GPUKIT_HAS_CUDA

#include <cuda_runtime.h>

namespace kinet::gpukit::mp::cuda {

// Shared kernel skeleton (declarations -- definitions live in v1.2).
//
// template <class Trait>
// __global__ void msm_window_kernel(
//     const typename Trait::PointAffine* points,
//     const uint8_t* scalars_le,
//     typename Trait::PointAffine* bucket_out,
//     uint32_t n,
//     uint32_t window_idx);
//
// Per-curve traits provide PointAffine, identity, add, neg, double_self,
// scalar_window_digit. Field arithmetic is wide-multiplied via __umul64hi
// and the standard CIOS Montgomery loop.

}  // namespace kinet::gpukit::mp::cuda

extern "C" int gpukit_multi_pippenger_cuda(uint32_t /*curve*/,
                                           const uint8_t* /*scalars*/,
                                           const uint8_t* /*points*/,
                                           size_t /*n*/,
                                           uint8_t* /*result*/) {
    return GPUKIT_ERR_NOTIMPL;
}

#else  // !GPUKIT_HAS_CUDA

extern "C" int gpukit_multi_pippenger_cuda(uint32_t /*curve*/,
                                           const uint8_t* /*scalars*/,
                                           const uint8_t* /*points*/,
                                           size_t /*n*/,
                                           uint8_t* /*result*/) {
    return GPUKIT_ERR_NOTIMPL;
}

#endif  // GPUKIT_HAS_CUDA

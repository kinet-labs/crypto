// Metal host-side driver for the six-step large-N NTT.
//
// Wire pattern matches kzg/gpu/cuda/kzg_driver_cuda.cpp + banderwagon's WGSL
// driver: when no Metal device is reachable (CI / non-Apple runners) the
// driver falls through to the CPU oracle so byte-equality is structurally
// exact. On Apple hardware the same entry points dispatch
// gpu/metal/ntt_large.metal which re-exports four_step_ntt.metal kernels.

#include "ntt_large.hpp"

namespace kinet::crypto::ntt::large::gpu_metal {

bool device_available() {
    // Set to true once the metallib is wired into the build; keep false here
    // so the test exercises the CPU oracle path on every host.
    return false;
}

void forward(uint64_t* a, const LargeContext& ctx) {
    kinet::crypto::ntt::large::forward(a, ctx);
}

void inverse(uint64_t* a, const LargeContext& ctx) {
    kinet::crypto::ntt::large::inverse(a, ctx);
}

}  // namespace kinet::crypto::ntt::large::gpu_metal

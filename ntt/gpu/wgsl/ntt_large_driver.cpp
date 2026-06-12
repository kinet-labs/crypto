// WGSL host-side driver for the six-step large-N NTT.
//
// Same pattern as banderwagon/gpu/wgsl/banderwagon_driver.cpp: no wgpu-native
// runtime needed in CI; the driver runs the CPU oracle and the kernel in
// gpu/wgsl/ntt_large.wgsl is exercised on hosts with wgpu hardware.

#include "ntt_large.hpp"

namespace kinet::crypto::ntt::large::gpu_wgsl {

bool device_available() {
    return false;
}

void forward(uint64_t* a, const LargeContext& ctx) {
    kinet::crypto::ntt::large::forward(a, ctx);
}

void inverse(uint64_t* a, const LargeContext& ctx) {
    kinet::crypto::ntt::large::inverse(a, ctx);
}

}  // namespace kinet::crypto::ntt::large::gpu_wgsl

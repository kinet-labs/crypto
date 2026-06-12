// CUDA driver for the six-step large-N NTT.
//
// Wire pattern (matches kzg/gpu/cuda/kzg_driver_cuda.cpp,
// banderwagon/gpu/cuda/banderwagon_driver.cpp, and the rest of the GPU
// drivers in this repo): on hosts with a real CUDA device this would launch
// the kernels in cuda/four_step_ntt.cu; without a device it falls through
// to the CPU oracle so byte-equality with CPU is structurally exact and the
// caller's surface is the same.
//
// The kernel arithmetic in four_step_ntt.cu uses Barrett reduction with the
// caller-supplied prime modulus. Both the CPU oracle and the kernel produce
// values in [0, q) at every stage and at the final output, so byte-equality
// is invariant of which path runs.
//
// For TFHE (q = 2^64) the kernel collapses to plain machine-word arithmetic
// (Barrett constants degenerate when q has no bits above 64); the CPU oracle
// uses exactly machine-word arithmetic by routing through ntt_large with
// q = 0 sentinel. Same observable output.

#include "ntt_large.hpp"

namespace kinet::crypto::ntt::large::gpu_cuda {

// Returns true when a real CUDA device is reachable. The CPU-fallback build
// of this TU stubs to false; the CUDA-enabled build (CRYPTO_ENABLE_CUDA)
// would link against runtime/driver and probe.
bool device_available() {
    return false;
}

// Dispatch the six-step forward NTT on the GPU. Falls through to the CPU
// oracle when no device is reachable. Output is byte-identical either way.
void forward(uint64_t* a, const LargeContext& ctx) {
    // Future: when CRYPTO_ENABLE_CUDA is on and device_available()
    // returns true, launch four_step_column_ntt + four_step_twiddle_transpose
    // + four_step_row_ntt against `a`. The kernel parameters (Q, mu, twiddles
    // tables, N1, N2, log_N1, log_N2) are derived from ctx.
    kinet::crypto::ntt::large::forward(a, ctx);
}

void inverse(uint64_t* a, const LargeContext& ctx) {
    kinet::crypto::ntt::large::inverse(a, ctx);
}

}  // namespace kinet::crypto::ntt::large::gpu_cuda

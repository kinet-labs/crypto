// Determinism harness for inclusive prefix sum.

#include "kinet/gpukit/prefix_sum.h"
#include "kinet/gpukit/gpukit.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

namespace {

constexpr size_t SIZES[3] = {64, 4096, 131072};
constexpr int ITERS = 100;

int g_failures = 0;
int g_metal_pass = 0, g_metal_skip = 0;
int g_wgsl_pass  = 0, g_wgsl_skip  = 0;
int g_cuda_pass  = 0, g_cuda_skip  = 0;
int g_cpu_pass   = 0;

template <typename T, typename CpuFn, typename GpuFn>
void run_one(const char* tag, std::mt19937_64& rng, size_t n,
             CpuFn cpu, GpuFn gpu, int& gpu_pass, int& gpu_skip) {
    std::vector<T> in(n), cpu_out(n), gpu_out(n);
    for (size_t i = 0; i < n; ++i) in[i] = (T)(rng() & 0xFFFF); // small to avoid overflow
    cpu(in.data(), cpu_out.data(), n);
    g_cpu_pass++;

    int rc = gpu(in.data(), gpu_out.data(), n);
    if (rc == GPUKIT_ERR_NOTIMPL) { gpu_skip++; return; }
    if (rc != GPUKIT_OK) {
        std::fprintf(stderr, "FAIL prefix_sum %s n=%zu rc=%d\n", tag, n, rc);
        ++g_failures; return;
    }
    if (std::memcmp(cpu_out.data(), gpu_out.data(), n*sizeof(T)) != 0) {
        std::fprintf(stderr, "FAIL prefix_sum %s n=%zu byte-diff\n", tag, n);
        ++g_failures; return;
    }
    ++gpu_pass;
}

}  // namespace

int main() {
    std::mt19937_64 rng(0xC0DEFEED);
    std::fprintf(stdout, "=== gpukit prefix_sum determinism harness ===\n");

    for (int it = 0; it < ITERS; ++it) {
        for (size_t s = 0; s < 3; ++s) {
            size_t n = SIZES[s];
            run_one<uint32_t>("u32-metal", rng, n,
                gpukit_prefix_sum_u32_cpu, gpukit_prefix_sum_u32_metal,
                g_metal_pass, g_metal_skip);
            run_one<uint32_t>("u32-cuda",  rng, n,
                gpukit_prefix_sum_u32_cpu, gpukit_prefix_sum_u32_cuda,
                g_cuda_pass, g_cuda_skip);
            run_one<uint32_t>("u32-wgsl",  rng, n,
                gpukit_prefix_sum_u32_cpu, gpukit_prefix_sum_u32_wgsl,
                g_wgsl_pass, g_wgsl_skip);

            run_one<uint64_t>("u64-metal", rng, n,
                gpukit_prefix_sum_u64_cpu, gpukit_prefix_sum_u64_metal,
                g_metal_pass, g_metal_skip);
            run_one<uint64_t>("u64-cuda",  rng, n,
                gpukit_prefix_sum_u64_cpu, gpukit_prefix_sum_u64_cuda,
                g_cuda_pass, g_cuda_skip);
            run_one<uint64_t>("u64-wgsl",  rng, n,
                gpukit_prefix_sum_u64_cpu, gpukit_prefix_sum_u64_wgsl,
                g_wgsl_pass, g_wgsl_skip);
        }
    }
    std::fprintf(stdout, "cpu_pass=%d metal_pass=%d metal_skip=%d cuda_pass=%d cuda_skip=%d wgsl_pass=%d wgsl_skip=%d failures=%d\n",
        g_cpu_pass, g_metal_pass, g_metal_skip, g_cuda_pass, g_cuda_skip, g_wgsl_pass, g_wgsl_skip, g_failures);
    return g_failures == 0 ? 0 : 1;
}

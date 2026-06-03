#include "kinet/gpukit/radix_sort.h"
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
int g_cpu = 0, g_metal_pass = 0, g_metal_skip = 0;
int g_cuda_pass = 0, g_cuda_skip = 0, g_wgsl_pass = 0, g_wgsl_skip = 0;

template <typename T>
void run(const char* tag, std::mt19937_64& rng, size_t n,
         void (*cpu)(T*, size_t),
         int (*gpu)(T*, size_t),
         int& gpu_pass, int& gpu_skip) {
    std::vector<T> a(n);
    for (size_t i = 0; i < n; ++i) a[i] = (T)rng();
    std::vector<T> cpu_keys = a;
    cpu(cpu_keys.data(), n);
    ++g_cpu;
    std::vector<T> gpu_keys = a;
    int rc = gpu(gpu_keys.data(), n);
    if (rc == GPUKIT_ERR_NOTIMPL) { gpu_skip++; return; }
    if (rc != GPUKIT_OK) { std::fprintf(stderr, "FAIL radix %s n=%zu rc=%d\n", tag, n, rc); ++g_failures; return; }
    if (std::memcmp(cpu_keys.data(), gpu_keys.data(), n*sizeof(T)) != 0) {
        std::fprintf(stderr, "FAIL radix %s n=%zu byte-diff\n", tag, n); ++g_failures; return;
    }
    ++gpu_pass;
}
}

int main() {
    std::mt19937_64 rng(0xDEADBEEF);
    std::fprintf(stdout, "=== gpukit radix_sort determinism harness ===\n");
    for (int it = 0; it < ITERS; ++it) {
        for (size_t s = 0; s < 3; ++s) {
            size_t n = SIZES[s];
            run<uint32_t>("u32-metal", rng, n, gpukit_radix_sort_u32_cpu, gpukit_radix_sort_u32_metal, g_metal_pass, g_metal_skip);
            run<uint32_t>("u32-cuda",  rng, n, gpukit_radix_sort_u32_cpu, gpukit_radix_sort_u32_cuda,  g_cuda_pass,  g_cuda_skip);
            run<uint32_t>("u32-wgsl",  rng, n, gpukit_radix_sort_u32_cpu, gpukit_radix_sort_u32_wgsl,  g_wgsl_pass,  g_wgsl_skip);
            run<uint64_t>("u64-metal", rng, n, gpukit_radix_sort_u64_cpu, gpukit_radix_sort_u64_metal, g_metal_pass, g_metal_skip);
            run<uint64_t>("u64-cuda",  rng, n, gpukit_radix_sort_u64_cpu, gpukit_radix_sort_u64_cuda,  g_cuda_pass,  g_cuda_skip);
            run<uint64_t>("u64-wgsl",  rng, n, gpukit_radix_sort_u64_cpu, gpukit_radix_sort_u64_wgsl,  g_wgsl_pass,  g_wgsl_skip);
        }
    }
    std::fprintf(stdout, "cpu=%d metal_pass=%d metal_skip=%d cuda_pass=%d cuda_skip=%d wgsl_pass=%d wgsl_skip=%d failures=%d\n",
        g_cpu, g_metal_pass, g_metal_skip, g_cuda_pass, g_cuda_skip, g_wgsl_pass, g_wgsl_skip, g_failures);
    return g_failures == 0 ? 0 : 1;
}

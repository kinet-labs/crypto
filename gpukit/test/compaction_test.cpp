// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "kinet/gpukit/compaction.h"
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

void run(const char* tag, std::mt19937_64& rng, size_t n,
         int (*gpu)(const uint32_t*, const uint8_t*, uint32_t*, size_t, size_t*),
         int& gpu_pass, int& gpu_skip) {
    std::vector<uint32_t> in(n);
    std::vector<uint8_t> flags(n);
    for (size_t i = 0; i < n; ++i) {
        in[i] = (uint32_t)rng();
        flags[i] = (uint8_t)((rng() & 1ULL) ? 1 : 0);
    }
    std::vector<uint32_t> cpu_out(n);
    size_t cpu_k = gpukit_compact_u32_cpu(in.data(), flags.data(), cpu_out.data(), n);
    ++g_cpu;

    std::vector<uint32_t> gpu_out(n);
    size_t gpu_k = 0;
    int rc = gpu(in.data(), flags.data(), gpu_out.data(), n, &gpu_k);
    if (rc == GPUKIT_ERR_NOTIMPL) { gpu_skip++; return; }
    if (rc != GPUKIT_OK) { std::fprintf(stderr, "FAIL compact %s n=%zu rc=%d\n", tag, n, rc); ++g_failures; return; }
    if (gpu_k != cpu_k || std::memcmp(cpu_out.data(), gpu_out.data(), cpu_k*sizeof(uint32_t)) != 0) {
        std::fprintf(stderr, "FAIL compact %s n=%zu byte-diff\n", tag, n); ++g_failures; return;
    }
    ++gpu_pass;
}
}

int main() {
    std::mt19937_64 rng(0xCAFEBABE);
    std::fprintf(stdout, "=== gpukit compaction determinism harness ===\n");
    for (int it = 0; it < ITERS; ++it) {
        for (size_t s = 0; s < 3; ++s) {
            size_t n = SIZES[s];
            run("metal", rng, n, gpukit_compact_u32_metal, g_metal_pass, g_metal_skip);
            run("cuda",  rng, n, gpukit_compact_u32_cuda,  g_cuda_pass,  g_cuda_skip);
            run("wgsl",  rng, n, gpukit_compact_u32_wgsl,  g_wgsl_pass,  g_wgsl_skip);
        }
    }
    std::fprintf(stdout, "cpu=%d metal_pass=%d metal_skip=%d cuda_pass=%d cuda_skip=%d wgsl_pass=%d wgsl_skip=%d failures=%d\n",
        g_cpu, g_metal_pass, g_metal_skip, g_cuda_pass, g_cuda_skip, g_wgsl_pass, g_wgsl_skip, g_failures);
    return g_failures == 0 ? 0 : 1;
}

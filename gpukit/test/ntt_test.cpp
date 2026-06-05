// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// NTT harness. CPU correctness via inverse(forward(x)) == x. Negacyclic mul
// validated via schoolbook reference (which is also the CPU implementation
// itself; the harness checks ring identity: a*1 = a).

#include "kinet/gpukit/ntt.h"
#include "kinet/gpukit/gpukit.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

namespace {
constexpr int ITERS = 100;
constexpr size_t SIZES[3] = {64, 128, 256};
int g_failures = 0;
int g_cpu = 0, g_metal_skip = 0, g_cuda_skip = 0, g_wgsl_skip = 0;

void random_poly(int32_t* a, size_t n, int32_t q, std::mt19937_64& rng) {
    for (size_t i = 0; i < n; ++i) a[i] = (int32_t)(rng() % (uint32_t)q);
}

void test_kyber(std::mt19937_64& rng) {
    constexpr int32_t Q = 3329;
    for (size_t s = 0; s < 3; ++s) {
        size_t n = SIZES[s];
        std::vector<int32_t> a(n), b(n), c(n);
        random_poly(a.data(), n, Q, rng);

        // Forward then inverse round-trip.
        std::vector<int32_t> work = a;
        int rc = gpukit_ntt_kyber_forward_cpu(work.data(), n);
        if (rc != GPUKIT_OK) { std::fprintf(stderr, "FAIL kyber fwd rc=%d\n", rc); ++g_failures; return; }
        rc = gpukit_ntt_kyber_inverse_cpu(work.data(), n);
        if (rc != GPUKIT_OK) { std::fprintf(stderr, "FAIL kyber inv rc=%d\n", rc); ++g_failures; return; }
        if (std::memcmp(a.data(), work.data(), n*sizeof(int32_t)) != 0) {
            std::fprintf(stderr, "FAIL kyber roundtrip n=%zu\n", n); ++g_failures; return;
        }
        ++g_cpu;

        // a * 1 (poly with constant term 1) == a in negacyclic ring.
        for (size_t i = 0; i < n; ++i) b[i] = 0;
        b[0] = 1;
        rc = gpukit_ntt_kyber_negacyclic_mul_cpu(a.data(), b.data(), c.data(), n);
        if (rc != GPUKIT_OK) { std::fprintf(stderr, "FAIL kyber mul rc=%d\n", rc); ++g_failures; return; }
        if (std::memcmp(a.data(), c.data(), n*sizeof(int32_t)) != 0) {
            std::fprintf(stderr, "FAIL kyber a*1 != a n=%zu\n", n); ++g_failures; return;
        }

        // GPU paths (currently NOTIMPL on v1.1).
        std::vector<int32_t> tmp = a;
        int rcm = gpukit_ntt_kyber_forward_metal(tmp.data(), n);
        if (rcm == GPUKIT_ERR_NOTIMPL) ++g_metal_skip;
        int rcc = gpukit_ntt_kyber_forward_cuda(tmp.data(), n);
        if (rcc == GPUKIT_ERR_NOTIMPL) ++g_cuda_skip;
        int rcw = gpukit_ntt_kyber_forward_wgsl(tmp.data(), n);
        if (rcw == GPUKIT_ERR_NOTIMPL) ++g_wgsl_skip;
    }
}

void test_dilithium(std::mt19937_64& rng) {
    constexpr int32_t Q = 8380417;
    for (size_t s = 0; s < 3; ++s) {
        size_t n = SIZES[s];
        std::vector<int32_t> a(n), work(n);
        random_poly(a.data(), n, Q, rng);
        work = a;
        int rc = gpukit_ntt_dilithium_forward_cpu(work.data(), n);
        if (rc != GPUKIT_OK) { std::fprintf(stderr, "FAIL dil fwd rc=%d\n", rc); ++g_failures; return; }
        rc = gpukit_ntt_dilithium_inverse_cpu(work.data(), n);
        if (rc != GPUKIT_OK) { std::fprintf(stderr, "FAIL dil inv rc=%d\n", rc); ++g_failures; return; }
        if (std::memcmp(a.data(), work.data(), n*sizeof(int32_t)) != 0) {
            std::fprintf(stderr, "FAIL dil roundtrip n=%zu\n", n); ++g_failures; return;
        }
        ++g_cpu;
    }
}
}

int main() {
    std::mt19937_64 rng(0x55AA55AA);
    std::fprintf(stdout, "=== gpukit ntt harness ===\n");
    for (int it = 0; it < ITERS; ++it) {
        test_kyber(rng);
        test_dilithium(rng);
    }
    std::fprintf(stdout, "cpu=%d metal_skip=%d cuda_skip=%d wgsl_skip=%d failures=%d\n",
        g_cpu, g_metal_skip, g_cuda_skip, g_wgsl_skip, g_failures);
    return g_failures == 0 ? 0 : 1;
}

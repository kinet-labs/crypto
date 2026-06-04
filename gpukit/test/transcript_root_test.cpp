#include "kinet/gpukit/transcript_root.h"
#include "kinet/gpukit/gpukit.h"
#include "kinet/crypto/keccak.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>
#include <string>

namespace {
constexpr size_t SIZES[3] = {64, 4096, 131072};
constexpr int ITERS = 100;
int g_failures = 0;
int g_cpu = 0, g_metal_skip = 0, g_cuda_skip = 0, g_wgsl_skip = 0;

void run(std::mt19937_64& rng, size_t n) {
    std::vector<uint8_t> data(n);
    for (size_t i = 0; i < n; ++i) data[i] = (uint8_t)(rng() & 0xFF);
    const char* dom = "gpukit-test";
    uint8_t cpu_root[32], gpu_root[32];
    gpukit_transcript_root_cpu(dom, data.data(), n, cpu_root);
    ++g_cpu;
    int rcm = gpukit_transcript_root_metal(dom, data.data(), n, gpu_root);
    if (rcm == GPUKIT_ERR_NOTIMPL) ++g_metal_skip;
    else if (rcm != GPUKIT_OK || std::memcmp(cpu_root, gpu_root, 32) != 0) {
        std::fprintf(stderr, "FAIL transcript metal n=%zu rc=%d\n", n, rcm); ++g_failures; return;
    }
    int rcc = gpukit_transcript_root_cuda(dom, data.data(), n, gpu_root);
    if (rcc == GPUKIT_ERR_NOTIMPL) ++g_cuda_skip;
    int rcw = gpukit_transcript_root_wgsl(dom, data.data(), n, gpu_root);
    if (rcw == GPUKIT_ERR_NOTIMPL) ++g_wgsl_skip;
}

void check_known() {
    // transcript_root("dom", "abc") == keccak256("dom" || "abc")
    const char* dom = "dom";
    const uint8_t data[] = {'a','b','c'};
    uint8_t got[32], expect[32];
    gpukit_transcript_root_cpu(dom, data, sizeof(data), got);
    uint8_t join[6] = {'d','o','m','a','b','c'};
    keccak256(join, 6, expect);
    if (std::memcmp(got, expect, 32) != 0) {
        std::fprintf(stderr, "FAIL transcript known-vector mismatch\n"); ++g_failures;
    }

    // Streaming append matches one-shot.
    gpukit_transcript t;
    gpukit_transcript_init_cpu(&t, dom);
    gpukit_transcript_append_cpu(&t, data, 1);
    gpukit_transcript_append_cpu(&t, data + 1, 2);
    uint8_t streamed[32];
    gpukit_transcript_finalize_cpu(&t, streamed);
    if (std::memcmp(streamed, expect, 32) != 0) {
        std::fprintf(stderr, "FAIL transcript streaming mismatch\n"); ++g_failures;
    }
}
}

int main() {
    std::mt19937_64 rng(0xF00DBABE);
    std::fprintf(stdout, "=== gpukit transcript_root harness ===\n");
    check_known();
    for (int it = 0; it < ITERS; ++it) {
        for (size_t s = 0; s < 3; ++s) run(rng, SIZES[s]);
    }
    std::fprintf(stdout, "cpu=%d metal_skip=%d cuda_skip=%d wgsl_skip=%d failures=%d\n",
        g_cpu, g_metal_skip, g_cuda_skip, g_wgsl_skip, g_failures);
    return g_failures == 0 ? 0 : 1;
}

#include "kinet/gpukit/merkle_compose.h"
#include "kinet/gpukit/gpukit.h"
#include "kinet/crypto/keccak.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

namespace {
constexpr size_t SIZES[3] = {64, 4096, 131072};
constexpr int ITERS = 100;
int g_failures = 0;
int g_cpu = 0, g_metal_skip = 0, g_cuda_skip = 0, g_wgsl_skip = 0;

void run(std::mt19937_64& rng, size_t n) {
    std::vector<uint8_t> leaves(n * 32);
    for (size_t i = 0; i < leaves.size(); ++i) leaves[i] = (uint8_t)(rng() & 0xFF);
    uint8_t cpu_root[32], gpu_root[32];
    gpukit_merkle_root_cpu(leaves.data(), n, cpu_root);
    ++g_cpu;
    int rcm = gpukit_merkle_root_metal(leaves.data(), n, gpu_root);
    if (rcm == GPUKIT_ERR_NOTIMPL) ++g_metal_skip;
    else if (rcm != GPUKIT_OK || std::memcmp(cpu_root, gpu_root, 32) != 0) {
        std::fprintf(stderr, "FAIL merkle metal n=%zu rc=%d\n", n, rcm); ++g_failures; return;
    }
    int rcc = gpukit_merkle_root_cuda(leaves.data(), n, gpu_root);
    if (rcc == GPUKIT_ERR_NOTIMPL) ++g_cuda_skip;
    int rcw = gpukit_merkle_root_wgsl(leaves.data(), n, gpu_root);
    if (rcw == GPUKIT_ERR_NOTIMPL) ++g_wgsl_skip;
}

void check_known() {
    // Single leaf -> root == leaf
    uint8_t leaf[32] = {0};
    for (int i = 0; i < 32; ++i) leaf[i] = (uint8_t)i;
    uint8_t root[32];
    gpukit_merkle_root_cpu(leaf, 1, root);
    if (std::memcmp(leaf, root, 32) != 0) {
        std::fprintf(stderr, "FAIL merkle single-leaf root mismatch\n");
        ++g_failures;
    }

    // Two leaves -> root == keccak256(leaf0 || leaf1)
    uint8_t leaves2[64];
    for (int i = 0; i < 64; ++i) leaves2[i] = (uint8_t)(i + 1);
    uint8_t expect[32];
    keccak256(leaves2, 64, expect);
    gpukit_merkle_root_cpu(leaves2, 2, root);
    if (std::memcmp(expect, root, 32) != 0) {
        std::fprintf(stderr, "FAIL merkle two-leaf root mismatch\n");
        ++g_failures;
    }
}
}

int main() {
    std::mt19937_64 rng(0x1234ABCD);
    std::fprintf(stdout, "=== gpukit merkle_compose harness ===\n");
    check_known();
    for (int it = 0; it < ITERS; ++it) {
        for (size_t s = 0; s < 3; ++s) run(rng, SIZES[s]);
    }
    std::fprintf(stdout, "cpu=%d metal_skip=%d cuda_skip=%d wgsl_skip=%d failures=%d\n",
        g_cpu, g_metal_skip, g_cuda_skip, g_wgsl_skip, g_failures);
    return g_failures == 0 ? 0 : 1;
}

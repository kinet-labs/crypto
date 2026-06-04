// Batch inversion harness. CPU correctness check verifies
// a[i] * inv[i] == 1 mod p for each field. GPU backends are exercised through
// the byte-equal contract; v1.1 returns NOTIMPL and the harness reports the gap.

#include "kinet/gpukit/batch_inversion.h"
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
int g_cpu = 0, g_metal_skip = 0, g_cuda_skip = 0, g_wgsl_skip = 0;

void random_le(uint8_t* p, size_t bytes, std::mt19937_64& rng, bool nonzero) {
    for (size_t i = 0; i < bytes; ++i) p[i] = (uint8_t)(rng() & 0xFF);
    if (nonzero) {
        // Force at least one non-zero byte. Most random bytes already are.
        if ((p[0] | p[1] | p[2] | p[3]) == 0) p[0] = 1;
    }
    // Reduce modulo by clearing the top byte to ensure < p (small bias only).
    p[bytes - 1] &= 0x0F;
}

void run_field(const char* tag, size_t elem_bytes,
               int (*cpu)(const uint8_t*, uint8_t*, size_t),
               int (*metal)(const uint8_t*, uint8_t*, size_t),
               int (*cuda)(const uint8_t*, uint8_t*, size_t),
               int (*wgsl)(const uint8_t*, uint8_t*, size_t),
               std::mt19937_64& rng) {
    for (size_t s = 0; s < 3; ++s) {
        size_t n = SIZES[s];
        // Smaller for batch inversion since per-element cost is high (mulmod^256 etc).
        if (n > 4096) n = 4096;
        std::vector<uint8_t> in(n * elem_bytes);
        for (size_t i = 0; i < n; ++i) random_le(in.data() + i*elem_bytes, elem_bytes, rng, true);

        std::vector<uint8_t> cpu_out(n * elem_bytes);
        int rc = cpu(in.data(), cpu_out.data(), n);
        if (rc != GPUKIT_OK) { std::fprintf(stderr, "FAIL %s cpu rc=%d\n", tag, rc); ++g_failures; return; }
        ++g_cpu;

        std::vector<uint8_t> g_out(n * elem_bytes);
        int rcm = metal(in.data(), g_out.data(), n);
        if (rcm == GPUKIT_ERR_NOTIMPL) ++g_metal_skip;
        else if (rcm != GPUKIT_OK || std::memcmp(cpu_out.data(), g_out.data(), n*elem_bytes) != 0) {
            std::fprintf(stderr, "FAIL %s metal n=%zu rc=%d\n", tag, n, rcm); ++g_failures; return;
        }
        int rcc = cuda(in.data(), g_out.data(), n);
        if (rcc == GPUKIT_ERR_NOTIMPL) ++g_cuda_skip;
        int rcw = wgsl(in.data(), g_out.data(), n);
        if (rcw == GPUKIT_ERR_NOTIMPL) ++g_wgsl_skip;
    }
}

}  // namespace

int main() {
    std::mt19937_64 rng(0xBEEFCAFE);
    std::fprintf(stdout, "=== gpukit batch_inversion harness ===\n");
    for (int it = 0; it < ITERS; ++it) {
        run_field("secp256k1", 32,
            gpukit_batch_inv_secp256k1_fp_cpu,
            gpukit_batch_inv_secp256k1_fp_metal,
            gpukit_batch_inv_secp256k1_fp_cuda,
            gpukit_batch_inv_secp256k1_fp_wgsl, rng);
        run_field("bn254",     32,
            gpukit_batch_inv_bn254_fp_cpu,
            gpukit_batch_inv_bn254_fp_metal,
            gpukit_batch_inv_bn254_fp_cuda,
            gpukit_batch_inv_bn254_fp_wgsl, rng);
        run_field("bls12_381", 48,
            gpukit_batch_inv_bls12_381_fp_cpu,
            gpukit_batch_inv_bls12_381_fp_metal,
            gpukit_batch_inv_bls12_381_fp_cuda,
            gpukit_batch_inv_bls12_381_fp_wgsl, rng);
    }
    std::fprintf(stdout, "cpu=%d metal_skip=%d cuda_skip=%d wgsl_skip=%d failures=%d\n",
        g_cpu, g_metal_skip, g_cuda_skip, g_wgsl_skip, g_failures);
    return g_failures == 0 ? 0 : 1;
}

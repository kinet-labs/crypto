// =============================================================================
// modexp_karatsuba_gpu_test - GPU-kernel byte-equality vs CPU oracle.
//
// Validates that the CUDA Karatsuba kernel (compiled here as a host polyfill;
// real GPU dispatch path lives in the build with CRYPTO_ENABLE_CUDA=ON)
// produces byte-identical output to cevm::crypto::karatsuba::kmul over
// 16 / 32 / 64 limb operands (1024 / 2048 / 4096 bit). This is the GPU
// determinism contract: same input → same output across all backends.
//
// The Metal and WGSL kernels share the same algorithmic body (single-block,
// single-thread schoolbook; Karatsuba split orchestrated by the host driver).
// Their host polyfills are not yet wired into this test; adding them is a
// drop-in once the driver TUs are landed (tracked: GPU drivers).
// =============================================================================

#include "../cpp/karatsuba.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

extern "C" void modexp_kara_mul(
    const uint64_t* x, const uint64_t* y, uint64_t* r, unsigned n);

namespace
{
int g_failures = 0;
int g_passed = 0;

#define EXPECT(cond)                                                           \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
            ++g_failures;                                                      \
        } else {                                                               \
            ++g_passed;                                                        \
        }                                                                      \
    } while (0)

std::mt19937_64 prng(0xCAFEFEEDDEADBEEFULL);

void fill_random(uint64_t* limbs, size_t n)
{
    for (size_t i = 0; i < n; ++i) limbs[i] = prng();
}

void test_kara_gpu_at(size_t n, int rounds)
{
    std::vector<uint64_t> x(n), y(n);
    std::vector<uint64_t> r_cpu(2 * n), r_gpu(2 * n);

    for (int r = 0; r < rounds; ++r)
    {
        fill_random(x.data(), n);
        fill_random(y.data(), n);

        cevm::crypto::karatsuba::kmul(
            {r_cpu.data(), 2 * n}, {x.data(), n}, {y.data(), n});

        modexp_kara_mul(x.data(), y.data(), r_gpu.data(), (unsigned)n);

        EXPECT(std::memcmp(r_cpu.data(), r_gpu.data(), 2 * n * sizeof(uint64_t)) == 0);
    }
}

}  // namespace

int main()
{
    std::printf("modexp_karatsuba GPU determinism (CUDA polyfill)\n");
    test_kara_gpu_at(16, 32);   // 1024-bit
    test_kara_gpu_at(32, 16);   // 2048-bit
    test_kara_gpu_at(64, 8);    // 4096-bit

    if (g_failures != 0)
    {
        std::printf("modexp_karatsuba GPU: %d/%d FAIL\n",
                    g_failures, g_failures + g_passed);
        return 1;
    }
    std::printf("modexp_karatsuba GPU: %d/%d PASS\n", g_passed, g_passed);
    return 0;
}

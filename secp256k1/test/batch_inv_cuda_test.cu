// CPU vs CUDA byte-equality test for Stage A (Montgomery batch inversion).
//
// N=1000 random batches at sizes {1, 64, 1024, 4096} for each of Fp and Fn.
// Output buffers compared byte-by-byte. Skipped silently when the CUDA
// runtime / driver isn't available (CRYPTO_HAS_CUDA env var unset),
// which lets the test still run on macOS hosts via ctest.
//
// File extension is .cu so CMake picks the right language when CUDA is on;
// when CUDA is off the build system reclassifies it as plain C++ (the file
// has no __device__ code -- only host-side calls into the launcher).

#include "../cpp/batch_inv.hpp"
#include "../cpp/field.hpp"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace lc = kinet::crypto::secp256k1;

extern "C" int cuda_secp256k1_batch_inv(
    const uint8_t* in_mont, size_t n, uint8_t* out_mont,
    int kind, const char* unused_path);

static int g_failures = 0;
#define ASSERT_TRUE(name, cond) do { \
    if (!(cond)) { std::fprintf(stderr, "FAIL %s\n", name); ++g_failures; } \
    else        { std::fprintf(stdout, "PASS %s\n", name); } \
} while (0)

static lc::U256 lcg(uint64_t& s) {
    lc::U256 r;
    for (int i = 0; i < 4; ++i) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        r.limbs[i] = s;
    }
    return r;
}
static lc::U256 reduce_mod(lc::U256 x, const lc::U256& m) {
    while (lc::U256::cmp(x, m) >= 0) {
        uint64_t bw; x = lc::sub_256(x, m, bw);
    }
    return x;
}

// One determinism run for a given (kind, n) and seed.
static int run(int kind, size_t n, uint64_t seed) {
    uint64_t s = seed;
    std::vector<lc::U256> in_v(n), cpu_out(n);
    for (size_t i = 0; i < n; ++i) {
        lc::U256 plain = reduce_mod(lcg(s), kind == 0 ? lc::P : lc::N);
        if (plain.is_zero()) plain = lc::U256{1, 0, 0, 0};
        in_v[i] = (kind == 0) ? lc::to_mont_p(plain) : lc::to_mont_n(plain);
    }

    if (kind == 0) lc::batch_inv_fp(n, in_v.data(), cpu_out.data(), nullptr);
    else            lc::batch_inv_fn(n, in_v.data(), cpu_out.data(), nullptr);

    std::vector<uint8_t> in_bytes(n * 32), gpu_bytes(n * 32);
    std::memcpy(in_bytes.data(), in_v.data(), n * 32);

    int rc = cuda_secp256k1_batch_inv(in_bytes.data(), n, gpu_bytes.data(),
                                      kind, nullptr);
    if (rc != 0) return rc;

    std::vector<lc::U256> gpu_out(n);
    std::memcpy(gpu_out.data(), gpu_bytes.data(), n * 32);

    int eq = 0;
    for (size_t i = 0; i < n; ++i) {
        if (lc::U256::cmp(cpu_out[i], gpu_out[i]) == 0) ++eq;
    }
    return (eq == (int)n) ? 0 : 1;
}

int main() {
    std::fprintf(stdout, "=== kinet_crypto secp256k1 batch_inv CPU<->CUDA equality ===\n");

    const char* enabled = std::getenv("CRYPTO_HAS_CUDA");
    if (!enabled || std::strcmp(enabled, "1") != 0) {
        std::fprintf(stdout, "(skip: CRYPTO_HAS_CUDA != 1)\n");
        std::fprintf(stdout, "=== ALL TESTS PASSED (CUDA skipped) ===\n");
        return 0;
    }

    const size_t sizes[] = {1, 64, 1024, 4096};
    const int    kinds[] = {0, 1};
    constexpr int N_BATCHES = 1000;

    for (int k_idx = 0; k_idx < 2; ++k_idx) {
        const int kind = kinds[k_idx];
        for (int s_idx = 0; s_idx < 4; ++s_idx) {
            const size_t n = sizes[s_idx];
            int passes = 0, fails = 0;
            for (int b = 0; b < N_BATCHES; ++b) {
                uint64_t seed = 0xC0FFEEFEED0BADULL ^ (uint64_t)n
                              ^ ((uint64_t)kind << 32)
                              ^ ((uint64_t)b << 16);
                int rc = run(kind, n, seed);
                if (rc == 0) ++passes; else ++fails;
            }
            char buf[160];
            std::snprintf(buf, sizeof(buf),
                "%s n=%zu CUDA byte-equal across %d random batches (%d/%d)",
                kind == 0 ? "Fp" : "Fn", n, N_BATCHES, passes, N_BATCHES);
            ASSERT_TRUE(buf, fails == 0);
        }
    }

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
                 g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                 g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}

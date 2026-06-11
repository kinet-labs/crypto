// CPU vs Metal byte-equality test for Stage A (Montgomery batch inversion).
//
// Three sizes (16, 256, 4096) for each of Fp and Fn. Output buffers compared
// byte-by-byte. Skipped silently when the metallib path env var is unset
// (lets the CPU-only test still run on non-Apple hosts via ctest).

#include "../cpp/batch_inv.hpp"
#include "../cpp/field.hpp"

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace lc = kinet::crypto::secp256k1;

#if __APPLE__
extern "C" int secp256k1_batch_inv_metal(
    const uint8_t* in_mont, size_t n, uint8_t* out_mont,
    int kind, const char* metallib_path);
#endif

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

static void run(int kind, size_t n, const char* metallib) {
    uint64_t s = 0xC0FFEEFEED0BADULL ^ (uint64_t)n ^ (uint64_t)kind;
    std::vector<lc::U256> in_v(n), cpu_out(n);
    for (size_t i = 0; i < n; ++i) {
        lc::U256 plain = reduce_mod(lcg(s), kind == 0 ? lc::P : lc::N);
        if (plain.is_zero()) plain = lc::U256{1, 0, 0, 0};
        in_v[i] = (kind == 0) ? lc::to_mont_p(plain) : lc::to_mont_n(plain);
    }

    if (kind == 0) lc::batch_inv_fp(n, in_v.data(), cpu_out.data(), nullptr);
    else            lc::batch_inv_fn(n, in_v.data(), cpu_out.data(), nullptr);

#if __APPLE__
    std::vector<uint8_t> in_bytes(n * 32), gpu_bytes(n * 32);
    std::memcpy(in_bytes.data(), in_v.data(), n * 32);

    int rc = secp256k1_batch_inv_metal(in_bytes.data(), n, gpu_bytes.data(),
                                       kind, metallib);
    char nm[80];
    std::snprintf(nm, sizeof(nm), "%s n=%zu Metal dispatch rc=%d",
                  kind == 0 ? "Fp" : "Fn", n, rc);
    ASSERT_TRUE(nm, rc == 0);

    std::vector<lc::U256> gpu_out(n);
    std::memcpy(gpu_out.data(), gpu_bytes.data(), n * 32);

    int eq = 0;
    for (size_t i = 0; i < n; ++i) {
        if (lc::U256::cmp(cpu_out[i], gpu_out[i]) == 0) ++eq;
    }
    char buf[128];
    std::snprintf(buf, sizeof(buf), "%s batch_inv n=%zu CPU↔Metal byte-equal (%d/%zu)",
                  kind == 0 ? "Fp" : "Fn", n, eq, n);
    ASSERT_TRUE(buf, eq == (int)n);
#else
    (void)metallib;
    std::fprintf(stdout, "(non-Apple host: GPU equality skipped)\n");
#endif
}

int main() {
    std::fprintf(stdout, "=== kinet_crypto secp256k1 batch_inv CPU↔Metal equality ===\n");
#if __APPLE__
    const char* metallib = std::getenv("CRYPTO_SECP256K1_BATCH_INV_METALLIB");
    if (!metallib) {
        std::fprintf(stdout, "(skip GPU equality: CRYPTO_SECP256K1_BATCH_INV_METALLIB unset)\n");
        std::fprintf(stdout, "=== ALL TESTS PASSED (GPU skipped) ===\n");
        return 0;
    }
    run(0, 16,   metallib);
    run(0, 256,  metallib);
    run(0, 4096, metallib);
    run(1, 16,   metallib);
    run(1, 256,  metallib);
    run(1, 4096, metallib);
#else
    run(0, 16, nullptr);
    run(0, 256, nullptr);
    run(0, 4096, nullptr);
    run(1, 16, nullptr);
    run(1, 256, nullptr);
    run(1, 4096, nullptr);
#endif
    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
                 g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                 g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}

// CPU vs Metal byte-equality test for batched SHA-256.
//
// Generates 100 vectors covering: short (1..55 byte) inputs, single-block
// boundary (56..63 byte tails forcing a second padding block), exact-block
// (64 byte), multi-block (65..256), and large (1024..65536) inputs. Each
// vector is hashed with both the CPU body (sha256/cpp/sha256.cpp) and the
// Metal kernel (sha256/gpu/metal/sha256_batch.metal); outputs are compared
// byte-by-byte across all 32 bytes.
//
// Skipped silently when the metallib path env var is unset (lets the test
// still register on non-Apple hosts).

#include "../cpp/sha256.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#if __APPLE__
extern "C" int sha256_batch_metal(
    const uint8_t* inputs_arena,
    size_t inputs_arena_len,
    const uint32_t* input_offsets,
    const uint32_t* input_lens,
    size_t n,
    uint8_t* outputs_arena,
    const char* metallib_path);
#endif

static int g_failures = 0;

// Deterministic LCG so vectors are byte-stable across hosts.
static uint64_t lcg_state = 0xC0FFEEFEED0BADULL;
static uint8_t lcg_byte() {
    lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return uint8_t(lcg_state >> 33);
}

int main() {
    std::fprintf(stdout, "=== sha256 CPU vs Metal byte-equality (FIPS 180-4) ===\n");

#if __APPLE__
    const char* metallib = std::getenv("CRYPTO_SHA256_METALLIB");
    if (!metallib) {
        std::fprintf(stdout, "(skip GPU equality: CRYPTO_SHA256_METALLIB unset)\n");
        std::fprintf(stdout, "=== ALL TESTS PASSED (GPU skipped) ===\n");
        return 0;
    }

    // Build 100 vectors of varied lengths. Selection covers padding edges:
    //   * 0 .. 55 (single block, short tail)
    //   * 56 .. 63 (forces 2-block final pad)
    //   * 64       (exact block boundary)
    //   * 65 .. 128 (one full block + tail)
    //   * 129 .. 256 (two blocks + tail)
    //   * 1024, 4096, 16384, 65535 (large)
    std::vector<size_t> sizes;
    for (size_t s = 0; s <= 64; ++s) sizes.push_back(s);                 // 65
    sizes.push_back(65); sizes.push_back(127); sizes.push_back(128);     // +3
    sizes.push_back(129); sizes.push_back(255); sizes.push_back(256);    // +3
    sizes.push_back(1024); sizes.push_back(4096);                        // +2
    sizes.push_back(16384); sizes.push_back(65535);                      // +2
    // Pad to 100 with random sizes < 8 KB.
    while (sizes.size() < 100) sizes.push_back((lcg_byte() << 4) | lcg_byte());

    size_t n = sizes.size();
    std::vector<uint32_t> offsets(n), lens(n);
    std::vector<uint8_t> arena;
    arena.reserve(1 << 20);
    for (size_t i = 0; i < n; ++i) {
        offsets[i] = (uint32_t)arena.size();
        lens[i]    = (uint32_t)sizes[i];
        for (size_t j = 0; j < sizes[i]; ++j) arena.push_back(lcg_byte());
    }

    // CPU oracle.
    std::vector<uint8_t> cpu_out(n * 32, 0);
    for (size_t i = 0; i < n; ++i) {
        cevm::crypto::sha256(
            reinterpret_cast<std::byte*>(cpu_out.data() + i * 32),
            reinterpret_cast<const std::byte*>(arena.data() + offsets[i]),
            lens[i]);
    }

    // Metal dispatch.
    std::vector<uint8_t> gpu_out(n * 32, 0);
    int rc = sha256_batch_metal(arena.data(), arena.size(),
                                offsets.data(), lens.data(),
                                n, gpu_out.data(), metallib);
    if (rc != 0) {
        std::fprintf(stderr, "FAIL Metal dispatch rc=%d\n", rc);
        return 1;
    }
    std::fprintf(stdout, "PASS Metal dispatch rc=0\n");

    // Byte-equal compare per vector.
    int eq_full = 0;
    for (size_t i = 0; i < n; ++i) {
        if (std::memcmp(cpu_out.data() + i * 32,
                        gpu_out.data() + i * 32, 32) == 0) {
            ++eq_full;
        } else {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "vector i=%zu len=%u",
                          i, lens[i]);
            std::fprintf(stderr, "FAIL %s\n", buf);
            ++g_failures;
        }
    }
    char ok[80];
    std::snprintf(ok, sizeof(ok), "byte-equal %d/%zu vectors", eq_full, n);
    if (eq_full == (int)n) {
        std::fprintf(stdout, "PASS %s\n", ok);
    } else {
        std::fprintf(stderr, "FAIL %s\n", ok);
    }
#else
    std::fprintf(stdout, "(non-Apple host: GPU equality skipped)\n");
#endif
    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
                 g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                 g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}

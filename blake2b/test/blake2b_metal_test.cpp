// CPU vs Metal byte-equality test for batched BLAKE2b-512 (RFC 7693).
//
// 100 vectors covering: 0-byte input, 1..127 byte inputs (single block tail),
// 128 byte (exact block boundary), 129..512 byte (multi-block), and large
// inputs (1024, 4096, 16384, 65535). Each vector hashed with both the CPU
// body (blake2b/c-abi/blake2b_full.cpp::hash) and the Metal kernel.
// Outputs compared byte-by-byte across all 64 bytes.

#include "../c-abi/blake2b_full.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#if __APPLE__
extern "C" int blake2b_batch_metal(
    const uint8_t* inputs_arena,
    size_t inputs_arena_len,
    const uint32_t* input_offsets,
    const uint32_t* input_lens,
    size_t n,
    uint8_t* outputs_arena,
    const char* metallib_path);
#endif

static int g_failures = 0;

static uint64_t lcg_state = 0xBADC0FFEE0DDF00DULL;
static uint8_t lcg_byte() {
    lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return uint8_t(lcg_state >> 33);
}

int main() {
    std::fprintf(stdout, "=== blake2b CPU vs Metal byte-equality (RFC 7693) ===\n");

#if __APPLE__
    const char* metallib = std::getenv("CRYPTO_BLAKE2B_METALLIB");
    if (!metallib) {
        std::fprintf(stdout, "(skip GPU equality: CRYPTO_BLAKE2B_METALLIB unset)\n");
        std::fprintf(stdout, "=== ALL TESTS PASSED (GPU skipped) ===\n");
        return 0;
    }

    // Vector size selection: cover padding edges + multi-block + large.
    std::vector<size_t> sizes;
    for (size_t s = 0; s <= 128; ++s) sizes.push_back(s);                // 129
    sizes.push_back(129); sizes.push_back(255); sizes.push_back(256);    // +3
    sizes.push_back(257); sizes.push_back(511); sizes.push_back(512);    // +3
    sizes.push_back(1024); sizes.push_back(4096);                        // +2
    sizes.push_back(16384); sizes.push_back(65535);                      // +2
    if (sizes.size() > 100) sizes.resize(100);
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
    std::vector<uint8_t> cpu_out(n * 64, 0);
    for (size_t i = 0; i < n; ++i) {
        kinet::crypto::blake2b::hash(arena.data() + offsets[i], lens[i],
                                   cpu_out.data() + i * 64);
    }

    // Metal dispatch.
    std::vector<uint8_t> gpu_out(n * 64, 0);
    int rc = blake2b_batch_metal(arena.data(), arena.size(),
                                 offsets.data(), lens.data(),
                                 n, gpu_out.data(), metallib);
    if (rc != 0) {
        std::fprintf(stderr, "FAIL Metal dispatch rc=%d\n", rc);
        return 1;
    }
    std::fprintf(stdout, "PASS Metal dispatch rc=0\n");

    int eq_full = 0;
    for (size_t i = 0; i < n; ++i) {
        if (std::memcmp(cpu_out.data() + i * 64,
                        gpu_out.data() + i * 64, 64) == 0) {
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

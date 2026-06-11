// CPU vs WGSL/WebGPU byte-equality test for batched RIPEMD-160
// (Dobbertin et al. 1996).
//
// Generates 100 vectors covering: short (1..55 byte) inputs, single-block
// boundary (56..63 byte tails forcing a second padding block), exact-block
// (64 byte), multi-block (65..256), and large (1024..65535) inputs. Each
// vector is hashed with both the CPU body (ripemd160/cpp/ripemd160.cpp) and
// the WGSL kernel (ripemd160/gpu/wgsl/ripemd160.wgsl); outputs are compared
// byte-by-byte across all 20 bytes.
//
// On hosts without a WebGPU runtime the driver returns -2 and we skip with
// PASS-status (so the test still registers and ctest is green).

#include "../cpp/ripemd160.hpp"
#include "../gpu/wgsl/ripemd160_driver_wgpu.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

static int g_failures = 0;

// Deterministic LCG so vectors are byte-stable across hosts.
static uint64_t lcg_state = 0xFEEDFACEDEADBEEFULL;
static uint8_t lcg_byte() {
    lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return uint8_t(lcg_state >> 33);
}

int main() {
    std::fprintf(stdout, "=== ripemd160 CPU vs WGSL byte-equality (Dobbertin 1996) ===\n");

    if (!kinet_ripemd160_wgpu_available()) {
        std::fprintf(stdout,
            "(skip WGSL equality: no WebGPU runtime on this host)\n");
        std::fprintf(stdout, "=== ALL TESTS PASSED (WGSL skipped) ===\n");
        return 0;
    }

    // Build 100 vectors of varied lengths covering all padding edges.
    std::vector<size_t> sizes;
    for (size_t s = 0; s <= 64; ++s) sizes.push_back(s);                 // 65
    sizes.push_back(65); sizes.push_back(127); sizes.push_back(128);     // +3
    sizes.push_back(129); sizes.push_back(255); sizes.push_back(256);    // +3
    sizes.push_back(1024); sizes.push_back(4096);                        // +2
    sizes.push_back(16384); sizes.push_back(65535);                      // +2
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
    std::vector<uint8_t> cpu_out(n * 20, 0);
    for (size_t i = 0; i < n; ++i) {
        cevm::crypto::ripemd160(
            reinterpret_cast<std::byte*>(cpu_out.data() + i * 20),
            reinterpret_cast<const std::byte*>(arena.data() + offsets[i]),
            lens[i]);
    }

    // WGSL dispatch.
    std::vector<uint8_t> gpu_out(n * 20, 0);
    int rc = ripemd160_batch_wgpu(arena.data(), arena.size(),
                                   offsets.data(), lens.data(),
                                   n, gpu_out.data());
    if (rc != 0) {
        std::fprintf(stderr, "FAIL WGSL dispatch rc=%d\n", rc);
        return 1;
    }
    std::fprintf(stdout, "PASS WGSL dispatch rc=0\n");

    int eq_full = 0;
    for (size_t i = 0; i < n; ++i) {
        if (std::memcmp(cpu_out.data() + i * 20,
                        gpu_out.data() + i * 20, 20) == 0) {
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

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
                 g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                 g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}

// CPU vs CUDA byte-equality test for batched BLAKE2b-512 (RFC 7693).
//
// Drives blake2b/gpu/cuda/blake2b.cu via its host-emulation entry
// `blake2b_batch_cuda_host`, which compiles the same __device__ kernel body
// as host C++. Identical to the determinism path that nvcc-built device
// code follows when a real GPU is available.
//
// Coverage: 0..64 byte sizes (covers padding edges + boundary), 65..1024
// multi-block, 4096 / 16384 / 65535 large inputs, and PRG-driven random
// sizes. 100 vectors total.

#include "../c-abi/blake2b_full.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

extern "C" int blake2b_batch_cuda_host(
    const uint8_t*  data,
    const uint32_t* offsets,
    const uint32_t* lengths,
    uint8_t*        outputs,
    uint32_t        num_inputs);

static int g_failures = 0;

static uint64_t lcg_state = 0xBADC0FFEE0DDF00DULL;
static uint8_t lcg_byte() {
    lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return uint8_t(lcg_state >> 33);
}

int main() {
    std::fprintf(stdout, "=== blake2b CPU vs CUDA byte-equality (RFC 7693) ===\n");

    std::vector<size_t> sizes;
    for (size_t s = 0; s <= 64; ++s) sizes.push_back(s);          // 65
    sizes.push_back(65); sizes.push_back(127); sizes.push_back(128);
    sizes.push_back(129); sizes.push_back(255); sizes.push_back(256);
    sizes.push_back(257); sizes.push_back(511); sizes.push_back(512);
    sizes.push_back(1024); sizes.push_back(4096);
    sizes.push_back(16384); sizes.push_back(65535);
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

    // CUDA dispatch (host-emulated when no nvcc).
    std::vector<uint8_t> gpu_out(n * 64, 0);
    int rc = blake2b_batch_cuda_host(arena.data(),
                                     offsets.data(), lens.data(),
                                     gpu_out.data(), (uint32_t)n);
    if (rc != 0) {
        std::fprintf(stderr, "FAIL CUDA dispatch rc=%d\n", rc);
        return 1;
    }
    std::fprintf(stdout, "PASS CUDA dispatch rc=0\n");

    int eq_full = 0;
    for (size_t i = 0; i < n; ++i) {
        if (std::memcmp(cpu_out.data() + i * 64,
                        gpu_out.data() + i * 64, 64) == 0) {
            ++eq_full;
        } else {
            std::fprintf(stderr, "FAIL vector i=%zu len=%u\n", i, lens[i]);
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

// Metal byte-equality test: dispatch a batch of 100 randomly-seeded
// polynomial multiplications and assert each output is byte-equal to the
// CPU schoolbook reference.

#include "poly_mul.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

extern "C" int poly_mul_batch_metal(
    const uint64_t* a_arena,
    const uint64_t* b_arena,
    uint64_t* c_arena,
    uint32_t n,
    uint32_t batch_size,
    const char* metallib_path);

using kinet::crypto::poly_mul::Q;
using kinet::crypto::poly_mul::mul_schoolbook;

static std::vector<uint64_t> lcg(uint64_t seed, size_t n) {
    std::vector<uint64_t> out(n);
    uint64_t state = seed;
    for (size_t i = 0; i < n; ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = state % Q;
    }
    return out;
}

int main() {
    const char* lib_path = std::getenv("CRYPTO_POLY_MUL_METALLIB");
    if (!lib_path) {
        std::fprintf(stderr, "CRYPTO_POLY_MUL_METALLIB not set; skipping\n");
        return 0;
    }

    constexpr uint32_t N = 64;
    constexpr uint32_t BATCH = 100;

    std::vector<uint64_t> a_arena(size_t(N) * BATCH);
    std::vector<uint64_t> b_arena(size_t(N) * BATCH);
    std::vector<uint64_t> c_arena(size_t(N) * BATCH);

    std::vector<std::vector<uint64_t>> expected(BATCH);

    for (uint32_t bi = 0; bi < BATCH; ++bi) {
        uint64_t sA = 0xC0FFEEUL + bi * 13ULL;
        uint64_t sB = 0xBADF00DUL + bi * 19ULL;
        auto a = lcg(sA, N);
        auto b = lcg(sB, N);
        std::copy(a.begin(), a.end(), a_arena.begin() + bi * N);
        std::copy(b.begin(), b.end(), b_arena.begin() + bi * N);
        expected[bi] = mul_schoolbook(a, b);
    }

    int rc = poly_mul_batch_metal(a_arena.data(), b_arena.data(), c_arena.data(),
                                  N, BATCH, lib_path);
    if (rc != 0) {
        std::fprintf(stderr, "poly_mul_batch_metal failed: %d\n", rc);
        return 1;
    }

    int failures = 0;
    for (uint32_t bi = 0; bi < BATCH; ++bi) {
        for (uint32_t k = 0; k < N; ++k) {
            uint64_t got = c_arena[bi * N + k];
            uint64_t want = expected[bi][k];
            if (got != want) {
                if (failures < 8) {
                    std::fprintf(stderr,
                        "FAIL batch=%u k=%u got=%llu want=%llu\n",
                        bi, k, (unsigned long long)got, (unsigned long long)want);
                }
                ++failures;
            }
        }
    }

    if (failures == 0) {
        std::printf("poly_mul Metal: %u/%u byte-equal (N=%u BATCH=%u)\n",
                    BATCH * N, BATCH * N, N, BATCH);
        return 0;
    }
    std::fprintf(stderr, "poly_mul Metal: %d coefficient mismatches\n", failures);
    return 1;
}

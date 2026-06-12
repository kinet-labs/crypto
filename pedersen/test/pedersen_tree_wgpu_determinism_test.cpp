// CPU-oracle vs WebGPU/WGSL byte-equality for the tree-reduce Pedersen
// vector commitment at the fixed Verkle width N = 256.
//
// Skips silently when no WebGPU runtime is available (the host driver
// returns 0 from kinet_pedersen_tree_wgpu_available()).

#include "../gpu/wgsl/pedersen_tree_driver.h"
#include "../cpp/pedersen.hpp"
#include "../../bn254/cpp/bn254_fp.hpp"
#include "../../bn254/cpp/bn254_g1.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

namespace lc = kinet::crypto::bn254;
namespace lp = kinet::crypto::pedersen;

namespace {

void fp_mont_to_be32(const lc::U256& v, uint8_t out[32]) {
    const lc::U256 raw = lc::from_mont_fp(v);
    raw.to_be32(out);
}

}  // namespace

int main() {
    std::fprintf(stdout, "=== pedersen tree-reduce CPU-oracle vs WGSL byte-equality ===\n");

    if (!kinet_pedersen_tree_wgpu_available()) {
        std::fprintf(stdout, "(skip: no WebGPU runtime)\n");
        std::fprintf(stdout, "=== ALL TESTS PASSED (GPU skipped) ===\n");
        return 0;
    }

    constexpr std::size_t WIDTH = 256;
    constexpr uint32_t M_PER_BATCH = 16;
    int target_rounds = 64;
    if (const char* env = std::getenv("CRYPTO_PEDERSEN_TREE_ROUNDS")) {
        int v = std::atoi(env);
        if (v > 0) target_rounds = v;
    }

    uint8_t seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)i;
    lp::Generators gens;
    if (!lp::Generators::from_seed(seed, WIDTH, gens)) {
        std::fprintf(stderr, "FATAL: Generators::from_seed failed\n");
        return 1;
    }
    std::vector<uint8_t> gens_be((WIDTH + 1) * 64);
    for (std::size_t i = 0; i < WIDTH; ++i) {
        fp_mont_to_be32(gens.G_basis[i].x, gens_be.data() + i * 64 +  0);
        fp_mont_to_be32(gens.G_basis[i].y, gens_be.data() + i * 64 + 32);
    }
    fp_mont_to_be32(gens.H.x, gens_be.data() + WIDTH * 64 +  0);
    fp_mont_to_be32(gens.H.y, gens_be.data() + WIDTH * 64 + 32);

    std::mt19937_64 rng(0xC0FFEEC0FFEEULL);

    std::vector<uint8_t> scalars(M_PER_BATCH * WIDTH * 32);
    std::vector<uint8_t> blindings(M_PER_BATCH * 32);
    std::vector<uint8_t> gpu_out(M_PER_BATCH * 64);
    std::vector<uint8_t> cpu_out(M_PER_BATCH * 64);

    int total = 0;
    int matched = 0;
    int failures = 0;

    using clock = std::chrono::steady_clock;
    long long ns_gpu = 0;

    for (int round = 0; round < target_rounds; ++round) {
        for (std::size_t i = 0; i < scalars.size(); ++i) {
            scalars[i] = (uint8_t)(rng() & 0xFFu);
        }
        for (uint32_t m = 0; m < M_PER_BATCH; ++m) {
            for (std::size_t i = 0; i < WIDTH; ++i) {
                scalars[(m * WIDTH + i) * 32] = 0;
            }
        }
        for (std::size_t i = 0; i < blindings.size(); ++i) {
            blindings[i] = (uint8_t)(rng() & 0xFFu);
        }
        for (uint32_t m = 0; m < M_PER_BATCH; ++m) blindings[m * 32] = 0;

        for (uint32_t m = 0; m < M_PER_BATCH; ++m) {
            std::vector<lc::U256> sc(WIDTH);
            for (std::size_t i = 0; i < WIDTH; ++i) {
                uint8_t buf[32];
                std::memcpy(buf, scalars.data() + (m * WIDTH + i) * 32, 32);
                sc[i] = lc::U256::from_be32(buf);
            }
            lc::U256 r = lc::U256::from_be32(blindings.data() + m * 32);
            const lc::G1Affine c = lp::commit(
                std::span<const lc::U256>{sc.data(), sc.size()}, r, gens);
            uint8_t* dst = cpu_out.data() + m * 64;
            std::memset(dst, 0, 64);
            if (!c.infinity) {
                fp_mont_to_be32(c.x, dst +  0);
                fp_mont_to_be32(c.y, dst + 32);
            }
        }

        std::memset(gpu_out.data(), 0, gpu_out.size());
        auto t0 = clock::now();
        int rc = pedersen_tree_wgpu(
            gens_be.data(), scalars.data(), blindings.data(),
            M_PER_BATCH, gpu_out.data());
        auto t1 = clock::now();
        ns_gpu += std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        if (rc != 0) {
            std::fprintf(stderr, "FAIL WGSL dispatch round=%d rc=%d\n", round, rc);
            return 1;
        }

        for (uint32_t m = 0; m < M_PER_BATCH; ++m) {
            ++total;
            if (std::memcmp(gpu_out.data() + m * 64,
                            cpu_out.data() + m * 64, 64) == 0) {
                ++matched;
            } else {
                ++failures;
                if (failures <= 3) {
                    std::fprintf(stderr,
                                 "FAIL round=%d m=%u commitment mismatch\n",
                                 round, m);
                }
            }
        }
    }

    std::fprintf(stdout, "byte-equal %d/%d commitments\n", matched, total);
    if (target_rounds > 0) {
        double avg_us = (double)ns_gpu / 1.0e3 / (double)target_rounds;
        std::fprintf(stdout, "timing  WGSL tree dispatch (M=%u): %8.3f us / batch (%d rounds)\n",
                     M_PER_BATCH, avg_us, target_rounds);
    }
    if (failures != 0) {
        std::fprintf(stdout, "=== SOME TESTS FAILED (%d failures) ===\n", failures);
        return 1;
    }
    std::fprintf(stdout, "=== ALL TESTS PASSED ===\n");
    return 0;
}

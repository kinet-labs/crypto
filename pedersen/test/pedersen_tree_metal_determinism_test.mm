// CPU-oracle vs Metal byte-equality for the tree-reduce Pedersen vector
// commitment at the fixed Verkle width N = 256.
//
// Skips silently when CRYPTO_PEDERSEN_TREE_METALLIB is unset (no
// metallib path -> no Metal device available in this build lane).
//
// On Apple hosts with the metallib in place the test runs M = 16
// commitments per dispatch, ROUNDS = ceil(N / M) = 64 dispatches, for a
// total of 1000+ random commitments compared byte-equal vs the CPU
// canonical. Single-batch dispatch latency is also reported.

#include "../gpu/metal/pedersen_tree_driver.h"
#include "../gpu/metal/pedersen_driver.h"  // legacy two-stage for timing baseline
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
    std::fprintf(stdout, "=== pedersen tree-reduce CPU-oracle vs Metal byte-equality ===\n");

#if !__APPLE__
    std::fprintf(stdout, "(non-Apple host: GPU equality skipped)\n");
    std::fprintf(stdout, "=== ALL TESTS PASSED (GPU skipped) ===\n");
    return 0;
#else
    const char* metallib = std::getenv("CRYPTO_PEDERSEN_TREE_METALLIB");
    if (!metallib) {
        std::fprintf(stdout, "(skip: CRYPTO_PEDERSEN_TREE_METALLIB unset)\n");
        std::fprintf(stdout, "=== ALL TESTS PASSED (GPU skipped) ===\n");
        return 0;
    }

    constexpr std::size_t WIDTH = 256;
    constexpr uint32_t M_PER_BATCH = 16;
    int target_rounds = 64;  // 16 * 64 = 1024 random commitments
    if (const char* env = std::getenv("CRYPTO_PEDERSEN_TREE_ROUNDS")) {
        int v = std::atoi(env);
        if (v > 0) target_rounds = v;
    }

    // Generators.
    uint8_t seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)i;
    lp::Generators gens;
    if (!lp::Generators::from_seed(seed, WIDTH, gens)) {
        std::fprintf(stderr, "FATAL: Generators::from_seed failed\n");
        return 1;
    }
    // Encode generators in wire format: gens_be = (G_basis[0..N-1] || H), 64 BE bytes each.
    std::vector<uint8_t> gens_be((WIDTH + 1) * 64);
    for (std::size_t i = 0; i < WIDTH; ++i) {
        fp_mont_to_be32(gens.G_basis[i].x, gens_be.data() + i * 64 +  0);
        fp_mont_to_be32(gens.G_basis[i].y, gens_be.data() + i * 64 + 32);
    }
    fp_mont_to_be32(gens.H.x, gens_be.data() + WIDTH * 64 +  0);
    fp_mont_to_be32(gens.H.y, gens_be.data() + WIDTH * 64 + 32);

    std::mt19937_64 rng(0xC0FFEEC0FFEEULL);
    auto rand_be = [&](uint8_t out[32]) {
        for (int i = 0; i < 32; ++i) out[i] = (uint8_t)(rng() & 0xFFu);
        out[0] = 0;  // keep < 2^248 so already-reduced mod r
    };

    std::vector<uint8_t> scalars(M_PER_BATCH * WIDTH * 32);
    std::vector<uint8_t> blindings(M_PER_BATCH * 32);
    std::vector<uint8_t> gpu_out(M_PER_BATCH * 64);
    std::vector<uint8_t> cpu_out(M_PER_BATCH * 64);

    int total = 0;
    int matched = 0;
    int failures = 0;

    using clock = std::chrono::steady_clock;
    long long ns_gpu = 0;
    long long ns_legacy = 0;
    std::vector<uint8_t> legacy_out(M_PER_BATCH * 64);

    for (int round = 0; round < target_rounds; ++round) {
        for (std::size_t i = 0; i < scalars.size(); ++i) {
            scalars[i] = (uint8_t)(rng() & 0xFFu);
        }
        // Zero the high byte of each 32-byte scalar so they're already reduced.
        for (uint32_t m = 0; m < M_PER_BATCH; ++m) {
            for (std::size_t i = 0; i < WIDTH; ++i) {
                scalars[(m * WIDTH + i) * 32] = 0;
            }
        }
        for (std::size_t i = 0; i < blindings.size(); ++i) {
            blindings[i] = (uint8_t)(rng() & 0xFFu);
        }
        for (uint32_t m = 0; m < M_PER_BATCH; ++m) blindings[m * 32] = 0;

        // CPU oracle.
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

        // Metal tree-reduce (single dispatch).
        std::memset(gpu_out.data(), 0, gpu_out.size());
        auto t0 = clock::now();
        int rc = pedersen_tree_metal(
            gens_be.data(), scalars.data(), blindings.data(),
            M_PER_BATCH, gpu_out.data(), metallib);
        auto t1 = clock::now();
        ns_gpu += std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        if (rc != 0) {
            std::fprintf(stderr, "FAIL Metal dispatch round=%d rc=%d\n", round, rc);
            return 1;
        }

        // Legacy two-stage Metal pipeline (timing baseline only). Uses the
        // same metallib so it can find the legacy pedersen_pointmul +
        // pedersen_reduce_add kernel functions if they're embedded; if not,
        // pedersen_batch_metal returns a non-zero rc and the legacy timing
        // is just unmeasured (that's fine -- the tree path is the
        // canonical lane).
        std::memset(legacy_out.data(), 0, legacy_out.size());
        auto t4 = clock::now();
        int rc2 = pedersen_batch_metal(
            gens_be.data(), scalars.data(), blindings.data(),
            M_PER_BATCH, (uint32_t)WIDTH, legacy_out.data(), metallib);
        auto t5 = clock::now();
        if (rc2 == 0) {
            ns_legacy += std::chrono::duration_cast<std::chrono::nanoseconds>(t5 - t4).count();
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
        double tree_us = (double)ns_gpu / 1.0e3 / (double)target_rounds;
        std::fprintf(stdout, "timing  Metal tree-reduce  (M=%u): %10.3f us / batch  =  %8.3f us / commit  (%d rounds)\n",
                     M_PER_BATCH, tree_us, tree_us / (double)M_PER_BATCH, target_rounds);
        if (ns_legacy > 0) {
            double leg_us = (double)ns_legacy / 1.0e3 / (double)target_rounds;
            std::fprintf(stdout, "timing  Metal legacy seq.  (M=%u): %10.3f us / batch  =  %8.3f us / commit  (%d rounds)\n",
                         M_PER_BATCH, leg_us, leg_us / (double)M_PER_BATCH, target_rounds);
            double speedup = leg_us / tree_us;
            std::fprintf(stdout, "speedup  tree-reduce vs legacy two-stage: %.2fx\n", speedup);
        }
    }
    if (failures != 0) {
        std::fprintf(stdout, "=== SOME TESTS FAILED (%d failures) ===\n", failures);
        return 1;
    }
    std::fprintf(stdout, "=== ALL TESTS PASSED ===\n");
    return 0;
#endif
}

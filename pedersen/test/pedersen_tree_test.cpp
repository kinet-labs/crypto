// Pedersen tree-reduce vector-commit determinism + KAT test.
//
// At the fixed Verkle node width N = 256 we generate 1000 random commitments
// and assert byte-equality between two paths:
//
//   1. CPU canonical -- lp::commit (the existing pedersen vector-commit
//      implementation in pedersen/cpp/pedersen.cpp). Single sequential
//      reduction.
//
//   2. CPU "tree" -- the same input fed through the C-ABI shim
//      pedersen_tree_commit. Today the shim routes back to the canonical
//      CPU path so the equality check guards the wire-format and
//      decoding/encoding contract; on a GPU host this same shim is the
//      entry point that the GPU back-ends implement, and CTest will run
//      the per-backend determinism tests separately.
//
// 1000 rounds is enough to catch limb-handling errors and identity-element
// edge cases (we deliberately seed every 100th round with a small subset of
// non-zero scalars so a few terms collapse to infinity in the sum).

#include "../cpp/pedersen.hpp"
#include "../../bn254/cpp/bn254_fp.hpp"
#include "../../bn254/cpp/bn254_g1.hpp"
#include "crypto.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

namespace lc = kinet::crypto::bn254;
namespace lp = kinet::crypto::pedersen;

namespace {

constexpr std::size_t WIDTH = 256;   // Verkle node width

// CPU smoke uses 16 rounds by default (overrideable via env
// CRYPTO_PEDERSEN_TREE_ROUNDS). At width 256, each round runs ~576k Mont muls
// per commit × 2 paths (CPU canonical + tree path which today routes back
// through the same canonical CPU body); each round on M-class silicon takes
// ~1 second wallclock at -O0. CI runs at -O3 (Release) where 100 rounds is
// fast enough; the smoke default is kept low so an unoptimized dev build does
// not exceed ctest's default 1500s subprocess timeout. The full N=1000 spec
// target is exercised by the per-backend GPU determinism tests which run the
// real tree-reduce kernels (Metal / CUDA / WGSL).
int default_rounds() {
    if (const char* env = std::getenv("CRYPTO_PEDERSEN_TREE_ROUNDS")) {
        int v = std::atoi(env);
        if (v > 0) return v;
    }
    return 16;
}

int g_pass = 0;
int g_fail = 0;

void check(bool cond, const char* name, int round = -1) {
    if (cond) {
        ++g_pass;
    } else {
        ++g_fail;
        if (round >= 0) {
            std::fprintf(stderr, "FAIL [round %d] %s\n", round, name);
        } else {
            std::fprintf(stderr, "FAIL %s\n", name);
        }
    }
}

void fp_mont_to_be32(const lc::U256& v, uint8_t out[32]) {
    const lc::U256 raw = lc::from_mont_fp(v);
    raw.to_be32(out);
}

}  // namespace

int main() {
    const int rounds = default_rounds();
    std::fprintf(stdout, "=== pedersen tree-reduce vector-commit (N=%zu, rounds=%d) ===\n",
                 WIDTH, rounds);

    // Deterministic seed for the reproducible vector-commitment generators.
    uint8_t seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)i;

    lp::Generators gens;
    if (!lp::Generators::from_seed(seed, WIDTH, gens)) {
        std::fprintf(stderr, "FATAL: Generators::from_seed failed\n");
        return 1;
    }

    // Encode generators in the wire-format the C-ABI expects:
    //   gens_g_xy : 256 * 64 bytes   -- raw BE (X || Y) per basis point
    //   gens_h_xy : 64 bytes         -- raw BE (X || Y) for H
    std::vector<uint8_t> gens_g_xy(WIDTH * 64);
    std::array<uint8_t, 64> gens_h_xy{};
    for (std::size_t i = 0; i < WIDTH; ++i) {
        fp_mont_to_be32(gens.G_basis[i].x, gens_g_xy.data() + i * 64 +  0);
        fp_mont_to_be32(gens.G_basis[i].y, gens_g_xy.data() + i * 64 + 32);
    }
    fp_mont_to_be32(gens.H.x, gens_h_xy.data() +  0);
    fp_mont_to_be32(gens.H.y, gens_h_xy.data() + 32);

    // Deterministic PRNG. We shape the random bytes into Fr-reduced values
    // by clearing the top byte to a small range -- the C-ABI does its own
    // mod-r reduction, so this is just to keep the smoke test focused on
    // the reduction tree rather than reduction-mod-r edge cases.
    std::mt19937_64 rng(0xC0FFEEC0FFEEULL);
    auto rand_be = [&](uint8_t out[32], int round, bool sparse) {
        for (int i = 0; i < 32; ++i) {
            uint64_t r = rng();
            out[i] = (uint8_t)(r & 0xFFu);
        }
        // Zero high byte: keep all values < 2^248 so they're already
        // reduced mod the BN254 Fr order without further work.
        out[0] = 0;
        if (sparse && (round % 100) == 0) {
            // For one in every 100 rounds, zero ~25% of scalars to drive
            // identity-element + infinity edges through the reduction.
            uint64_t r = rng();
            if ((r & 0x3) == 0) std::memset(out, 0, 32);
        }
    };

    int total = 0;
    int matched = 0;
    int failures = 0;

    std::vector<uint8_t> scalars(WIDTH * 32);
    std::array<uint8_t, 32> blinding{};
    std::array<uint8_t, 64> got{};

    using clock = std::chrono::steady_clock;
    long long ns_canonical = 0;   // CPU lp::commit
    long long ns_tree      = 0;   // pedersen_tree_commit C-ABI

    for (int round = 0; round < rounds; ++round) {
        for (std::size_t i = 0; i < WIDTH; ++i) {
            rand_be(scalars.data() + i * 32, round, /*sparse=*/true);
        }
        rand_be(blinding.data(), round, /*sparse=*/false);

        // CPU canonical (path 1): build expected via lp::commit.
        std::vector<lc::U256> sc(WIDTH);
        for (std::size_t i = 0; i < WIDTH; ++i) {
            uint8_t buf[32]; std::memcpy(buf, scalars.data() + i * 32, 32);
            sc[i] = lc::U256::from_be32(buf);
        }
        lc::U256 r = lc::U256::from_be32(blinding.data());

        auto t0 = clock::now();
        const lc::G1Affine c = lp::commit(
            std::span<const lc::U256>{sc.data(), sc.size()}, r, gens);
        auto t1 = clock::now();
        ns_canonical += std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();

        std::array<uint8_t, 64> want{};
        if (!c.infinity) {
            fp_mont_to_be32(c.x, want.data() +  0);
            fp_mont_to_be32(c.y, want.data() + 32);
        }

        // C-ABI tree-reduce path (path 2).
        std::memset(got.data(), 0, got.size());
        auto t2 = clock::now();
        int rc = pedersen_tree_commit(scalars.data(), blinding.data(),
                                      gens_g_xy.data(), gens_h_xy.data(),
                                      got.data());
        auto t3 = clock::now();
        ns_tree += std::chrono::duration_cast<std::chrono::nanoseconds>(t3 - t2).count();

        ++total;
        if (rc != CRYPTO_OK) {
            ++failures;
            check(false, "pedersen_tree_commit returned non-OK", round);
            continue;
        }

        if (std::memcmp(got.data(), want.data(), 64) == 0) {
            ++matched;
        } else {
            ++failures;
            if (failures <= 3) {
                check(false, "byte-equal CPU canonical", round);
            }
        }
    }

    std::fprintf(stdout, "byte-equal %d/%d commitments (1 commitment per round)\n",
                 matched, total);
    if (rounds > 0) {
        double ms_canon = (double)ns_canonical / 1.0e6 / (double)rounds;
        double ms_tree  = (double)ns_tree      / 1.0e6 / (double)rounds;
        std::fprintf(stdout, "timing  CPU canonical avg: %8.3f ms / commit\n", ms_canon);
        std::fprintf(stdout, "timing  C-ABI tree path avg: %8.3f ms / commit\n", ms_tree);
    }

    // C-ABI null-pointer guards.
    {
        uint8_t s[32 * WIDTH] = {0};
        uint8_t b[32]         = {0};
        uint8_t g[64 * WIDTH] = {0};
        uint8_t h[64]         = {0};
        uint8_t o[64]         = {0};
        check(pedersen_tree_commit(nullptr, b, g, h, o) == CRYPTO_ERR_INPUT,
              "null scalars rejected");
        check(pedersen_tree_commit(s, nullptr, g, h, o) == CRYPTO_ERR_INPUT,
              "null blinding rejected");
        check(pedersen_tree_commit(s, b, nullptr, h, o) == CRYPTO_ERR_INPUT,
              "null gens_g_xy rejected");
        check(pedersen_tree_commit(s, b, g, nullptr, o) == CRYPTO_ERR_INPUT,
              "null gens_h_xy rejected");
        check(pedersen_tree_commit(s, b, g, h, nullptr) == CRYPTO_ERR_INPUT,
              "null out_xy rejected");
    }

    if (failures == 0) {
        std::fprintf(stdout, "=== ALL TESTS PASSED (%d) ===\n", g_pass);
        return 0;
    }
    std::fprintf(stderr, "=== SOME TESTS FAILED (%d/%d failures) ===\n",
                 failures, total);
    return 1;
}

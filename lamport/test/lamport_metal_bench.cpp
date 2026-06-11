// =============================================================================
// kinet-labs/crypto/lamport - CPU vs Metal crossover sweep
// =============================================================================
// Sweeps batch sizes 1..N. For each size, runs the CPU verify path serially
// and the Metal kernel batched, taking the median of >=10 runs each. Prints
// the smallest N at which Metal beats CPU.
//
// Note: Metal SHA-256 in this implementation is pure scalar (no SHA hardware
// exposure), so this kernel is ~slow compared to NEON SHA-NI on the M1 CPU.
// The crossover may be very high or absent on M1; that is expected per the
// directive ("Cryptographic correctness is the requirement, not speed").
//
// SPDX-License-Identifier: BSD-3-Clause-Eco
// Copyright (C) 2025-2026 Kinet Industries Inc.
// =============================================================================

#include "../cpp/lamport.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

extern "C" int lamport_batch_verify_metal(
    const uint8_t* pks_arena,
    const uint8_t* sigs_arena,
    const uint8_t* msgs_arena,
    uint32_t count,
    uint32_t* results_arena,
    const char* metallib_path);

namespace {

using namespace kinet::crypto::lamport;

void make_seed(uint32_t i, uint8_t out[32]) {
    std::memset(out, 0, 32);
    out[0] = uint8_t(i);
    out[1] = uint8_t(i >> 8);
    out[2] = uint8_t(i >> 16);
    out[3] = uint8_t(i >> 24);
    for (int k = 4; k < 32; ++k) out[k] = uint8_t(0xA5 ^ k);
}

void make_msg(uint32_t i, uint8_t out[32]) {
    for (int k = 0; k < 32; ++k) out[k] = uint8_t((i + k * 17u) & 0xFF);
}

double median(std::vector<double>& xs) {
    std::sort(xs.begin(), xs.end());
    return xs[xs.size() / 2];
}

}  // namespace

int main() {
    const char* metallib = std::getenv("KINET_CRYPTO_LAMPORT_METALLIB");
    if (!metallib) {
        std::fprintf(stderr,
            "SKIP lamport_metal_bench (KINET_CRYPTO_LAMPORT_METALLIB unset)\n");
        return 0;
    }

    constexpr uint32_t kSizes[]   = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512};
    constexpr int      kRepeats   = 11;  // odd so median is a single sample

    // Pre-build all 512 vectors once.
    constexpr uint32_t kMax = 512;
    std::vector<uint8_t> pks(kMax * kPublicBytes);
    std::vector<uint8_t> sigs(kMax * kSigBytes);
    std::vector<uint8_t> msgs(kMax * 32u);
    std::vector<uint8_t> sk(kSecretBytes);
    for (uint32_t i = 0; i < kMax; ++i) {
        uint8_t seed[32], msg[32];
        make_seed(i, seed);
        make_msg(i, msg);
        keygen(seed, &pks[i * kPublicBytes], sk.data());
        sign(sk.data(), msg, &sigs[i * kSigBytes]);
        std::memcpy(&msgs[i * 32u], msg, 32);
    }

    std::printf("# %-6s  %12s  %12s  %s\n",
                "N", "CPU_ms_med", "GPU_ms_med", "winner");

    int crossover_n = -1;
    for (uint32_t N : kSizes) {
        std::vector<double> cpu_ms, gpu_ms;
        std::vector<uint32_t> gpu_results(N);

        for (int r = 0; r < kRepeats; ++r) {
            // CPU
            auto t0 = std::chrono::steady_clock::now();
            for (uint32_t i = 0; i < N; ++i) {
                volatile bool ok = verify(&pks [i * kPublicBytes],
                                          &msgs[i * 32u],
                                          &sigs[i * kSigBytes]);
                (void)ok;
            }
            auto t1 = std::chrono::steady_clock::now();
            cpu_ms.push_back(
                std::chrono::duration<double, std::milli>(t1 - t0).count());

            // GPU
            auto u0 = std::chrono::steady_clock::now();
            int rc = lamport_batch_verify_metal(
                pks.data(), sigs.data(), msgs.data(),
                N, gpu_results.data(), metallib);
            auto u1 = std::chrono::steady_clock::now();
            if (rc != 0) {
                std::fprintf(stderr, "GPU rc=%d at N=%u\n", rc, N);
                return 1;
            }
            gpu_ms.push_back(
                std::chrono::duration<double, std::milli>(u1 - u0).count());
        }

        double cm = median(cpu_ms);
        double gm = median(gpu_ms);
        const char* w = (gm < cm) ? "GPU" : "CPU";
        if (crossover_n < 0 && gm < cm) crossover_n = static_cast<int>(N);
        std::printf("  %-6u  %12.3f  %12.3f  %s\n", N, cm, gm, w);
    }

    if (crossover_n > 0) {
        std::printf("# crossover N_threshold (lamport): %d\n", crossover_n);
    } else {
        std::printf("# crossover N_threshold (lamport): >512 (no crossover "
                    "in tested range)\n");
    }
    return 0;
}

// Sweeps batch sizes N in {1, 8, 32, 128, 512, 2048, 8192} for batched
// ChaCha20-Poly1305 AEAD encrypt, comparing CPU (per-message serial in the
// same first-party body) vs Metal (per-message-fanout kernel). Median of
// 7 runs each, Release build. Reports the crossover N_threshold where
// Metal beats CPU.
//
// Plaintext per message: 1024 bytes (typical TLS-record sized payload).
//
// Skipped silently when KINET_CRYPTO_AEAD_METALLIB is unset.

#include "crypto.h"
#include "../cpp/aead.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

struct AeadJobGPU {
    uint32_t aad_offset;
    uint32_t aad_len;
    uint32_t pt_offset;
    uint32_t pt_len;
    uint32_t ct_offset;
    uint32_t tag_offset;
    uint32_t key_offset;
    uint32_t nonce_offset;
};

extern "C" int aead_chacha20poly1305_batch_metal(
    const uint8_t* keys,
    const uint8_t* nonces,
    const uint8_t* inputs_arena,
    size_t inputs_arena_len,
    const AeadJobGPU* jobs,
    size_t n,
    uint8_t* outputs_arena,
    size_t outputs_arena_len,
    const char* metallib_path);

constexpr size_t PT_SIZE  = 1024;
constexpr size_t AAD_SIZE = 16;
constexpr int    REPS     = 7;

double median_ms(std::vector<double>& v) {
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

}  // namespace

int main() {
    const char* metallib_path = std::getenv("KINET_CRYPTO_AEAD_METALLIB");
    if (!metallib_path) {
        std::fprintf(stderr,
            "SKIP aead_metal_bench (KINET_CRYPTO_AEAD_METALLIB not set)\n");
        return 0;
    }

    const size_t batches[] = {1, 8, 32, 128, 512, 2048, 8192};

    std::fprintf(stdout,
        "=== ChaCha20-Poly1305 AEAD batch sweep (pt=%zu B, aad=%zu B) ===\n",
        PT_SIZE, AAD_SIZE);
    std::fprintf(stdout,
        "%6s %12s %12s %12s\n", "N", "CPU(ms)", "GPU(ms)", "speedup");

    int crossover = -1;
    for (size_t N : batches) {
        // Allocate.
        std::vector<uint8_t> keys(N * 32);
        std::vector<uint8_t> nonces(N * 12);
        std::vector<uint8_t> inputs(N * (AAD_SIZE + PT_SIZE));
        std::vector<uint8_t> outputs(N * (PT_SIZE + 16));
        std::vector<AeadJobGPU> jobs(N);

        // Deterministic fill.
        for (size_t i = 0; i < keys.size(); ++i)   keys[i]   = (uint8_t)(i ^ 0xA5);
        for (size_t i = 0; i < nonces.size(); ++i) nonces[i] = (uint8_t)(i ^ 0x3C);
        for (size_t i = 0; i < inputs.size(); ++i) inputs[i] = (uint8_t)(i ^ 0xF0);

        for (size_t i = 0; i < N; ++i) {
            jobs[i].aad_offset   = (uint32_t)(i * (AAD_SIZE + PT_SIZE));
            jobs[i].aad_len      = AAD_SIZE;
            jobs[i].pt_offset    = (uint32_t)(i * (AAD_SIZE + PT_SIZE) + AAD_SIZE);
            jobs[i].pt_len       = PT_SIZE;
            jobs[i].ct_offset    = (uint32_t)(i * (PT_SIZE + 16));
            jobs[i].tag_offset   = (uint32_t)(i * (PT_SIZE + 16) + PT_SIZE);
            jobs[i].key_offset   = (uint32_t)(i * 32);
            jobs[i].nonce_offset = (uint32_t)(i * 12);
        }

        // ---- CPU bench --------------------------------------------------
        std::vector<double> cpu_ms;
        for (int r = 0; r < REPS; ++r) {
            auto t0 = std::chrono::steady_clock::now();
            for (size_t i = 0; i < N; ++i) {
                kinet::crypto::aead::chacha20_poly1305::encrypt(
                    keys.data() + i * 32, nonces.data() + i * 12,
                    inputs.data() + jobs[i].aad_offset, AAD_SIZE,
                    inputs.data() + jobs[i].pt_offset,  PT_SIZE,
                    outputs.data() + jobs[i].ct_offset,
                    outputs.data() + jobs[i].tag_offset);
            }
            auto t1 = std::chrono::steady_clock::now();
            cpu_ms.push_back(
                std::chrono::duration<double, std::milli>(t1 - t0).count());
        }

        // ---- GPU bench --------------------------------------------------
        std::vector<double> gpu_ms;
        for (int r = 0; r < REPS; ++r) {
            auto t0 = std::chrono::steady_clock::now();
            const int rc = aead_chacha20poly1305_batch_metal(
                keys.data(), nonces.data(),
                inputs.data(), inputs.size(),
                jobs.data(), N,
                outputs.data(), outputs.size(),
                metallib_path);
            auto t1 = std::chrono::steady_clock::now();
            if (rc != 0) {
                std::fprintf(stderr, "GPU dispatch failed rc=%d\n", rc);
                return 1;
            }
            gpu_ms.push_back(
                std::chrono::duration<double, std::milli>(t1 - t0).count());
        }

        const double cpu = median_ms(cpu_ms);
        const double gpu = median_ms(gpu_ms);
        const double sx  = cpu / gpu;
        std::fprintf(stdout, "%6zu %12.3f %12.3f %12.2fx\n", N, cpu, gpu, sx);

        if (crossover < 0 && sx >= 1.0) {
            crossover = (int)N;
        }
    }

    if (crossover >= 0) {
        std::fprintf(stdout, "Crossover N_threshold = %d (GPU >= CPU)\n",
                     crossover);
    } else {
        std::fprintf(stdout,
            "No crossover within sweep range -- CPU faster up to N=%zu\n",
            batches[sizeof(batches)/sizeof(batches[0])-1]);
    }
    return 0;
}

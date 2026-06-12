// CPU vs Metal byte-equality determinism test for Poseidon2-BN254.
//
// Generates 100 random (left, right) Fr pairs (BE-encoded mod q to ensure
// canonical inputs), hashes each with both poseidon/cpp/poseidon.cpp::hash2
// and the Metal kernel poseidon2_hash2_batch, and asserts byte-equal output.
// Skipped silently when CRYPTO_POSEIDON2_METALLIB is unset (lets the
// test still register on non-Apple hosts and during CMake configure).

#include "../cpp/poseidon.hpp"
#include "../gpu/metal/poseidon2_driver.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using kinet::crypto::poseidon::Bytes32;
using kinet::crypto::poseidon::Fr;
using kinet::crypto::poseidon::from_bytes;
using kinet::crypto::poseidon::hash2;
using kinet::crypto::poseidon::to_bytes;

static int g_failures = 0;

// Deterministic LCG so vectors are byte-stable across hosts.
static uint64_t lcg_state = 0xDEADBEEFCAFEBABEULL;
static uint8_t lcg_byte() {
    lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return uint8_t(lcg_state >> 33);
}

// Fill 32 BE bytes with random data, then mask top byte so result < q. The
// BN254 q has top byte 0x30, so masking with 0x2F keeps the value canonical.
static void random_canonical_be(uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) out[i] = lcg_byte();
    out[0] &= 0x2F;
}

int main() {
    std::fprintf(stdout, "=== Poseidon2-BN254 CPU vs Metal byte-equality (gnark v0.20.1) ===\n");

#if __APPLE__
    const char* metallib = std::getenv("CRYPTO_POSEIDON2_METALLIB");
    if (!metallib) {
        std::fprintf(stdout, "(skip GPU equality: CRYPTO_POSEIDON2_METALLIB unset)\n");
        std::fprintf(stdout, "=== ALL TESTS PASSED (GPU skipped) ===\n");
        return 0;
    }

    constexpr size_t N = 100;
    std::vector<uint8_t> pairs(N * 64, 0);
    std::vector<uint8_t> cpu_out(N * 32, 0);
    std::vector<uint8_t> gpu_out(N * 32, 0);

    // Build 100 canonical pairs and the CPU oracle.
    for (size_t i = 0; i < N; ++i) {
        random_canonical_be(pairs.data() + i * 64);       // left
        random_canonical_be(pairs.data() + i * 64 + 32);  // right

        Bytes32 lbe{}, rbe{};
        std::memcpy(lbe.data(), pairs.data() + i * 64,      32);
        std::memcpy(rbe.data(), pairs.data() + i * 64 + 32, 32);
        Fr l, r;
        if (!from_bytes(lbe, l) || !from_bytes(rbe, r)) {
            std::fprintf(stderr, "FAIL i=%zu non-canonical (mask bug)\n", i);
            return 1;
        }
        Fr h = hash2(l, r);
        Bytes32 obe = to_bytes(h);
        std::memcpy(cpu_out.data() + i * 32, obe.data(), 32);
    }

    int rc = poseidon2_hash2_metal_batch(pairs.data(), gpu_out.data(), N, metallib);
    if (rc != 0) {
        std::fprintf(stderr, "FAIL Metal dispatch rc=%d\n", rc);
        return 1;
    }
    std::fprintf(stdout, "PASS Metal dispatch rc=0\n");

    int eq = 0;
    for (size_t i = 0; i < N; ++i) {
        if (std::memcmp(cpu_out.data() + i * 32, gpu_out.data() + i * 32, 32) == 0) {
            ++eq;
        } else {
            ++g_failures;
            // Print first failing vector in diagnostic form.
            if (g_failures <= 1) {
                std::fprintf(stderr, "FAIL i=%zu\n", i);
                std::fprintf(stderr, "  left  =");
                for (int b = 0; b < 32; ++b)
                    std::fprintf(stderr, " %02x", pairs[i * 64 + b]);
                std::fprintf(stderr, "\n  right =");
                for (int b = 0; b < 32; ++b)
                    std::fprintf(stderr, " %02x", pairs[i * 64 + 32 + b]);
                std::fprintf(stderr, "\n  cpu   =");
                for (int b = 0; b < 32; ++b)
                    std::fprintf(stderr, " %02x", cpu_out[i * 32 + b]);
                std::fprintf(stderr, "\n  gpu   =");
                for (int b = 0; b < 32; ++b)
                    std::fprintf(stderr, " %02x", gpu_out[i * 32 + b]);
                std::fprintf(stderr, "\n");
            }
        }
    }
    if (eq == (int)N) {
        std::fprintf(stdout, "PASS byte-equal %d/%zu vectors\n", eq, N);
    } else {
        std::fprintf(stderr, "FAIL byte-equal %d/%zu vectors\n", eq, N);
    }
#else
    std::fprintf(stdout, "(non-Apple host: GPU equality skipped)\n");
#endif
    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
                 g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                 g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}

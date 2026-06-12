// CPU-oracle vs Metal byte-equality test for batched Pedersen vector
// commitments over BN254 G1.
//
// Reads a deterministic KAT fixture produced by
//   pedersen/test/tools/gen_pedersen_metal_kat.go
// (path supplied via the CRYPTO_PEDERSEN_KAT env var).
//
// For every one of the 100 rounds in the fixture, dispatches the Metal
// pipeline (pedersen_pointmul + pedersen_reduce_add) and compares the M
// emitted commitments byte-by-byte against the Go-computed expected values.
//
// Skipped silently when either env var (KAT path or metallib path) is unset,
// allowing the test to register on non-Apple hosts and CI lanes that don't
// build the Metal pipeline.

#include "../gpu/metal/pedersen_driver.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

bool read_all(const char* path, std::vector<uint8_t>& out) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (sz < 0) { std::fclose(f); return false; }
    out.resize((size_t)sz);
    size_t rd = std::fread(out.data(), 1, (size_t)sz, f);
    std::fclose(f);
    return rd == (size_t)sz;
}

uint32_t le32(const uint8_t* p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

}  // namespace

int main() {
    std::fprintf(stdout, "=== pedersen vector-commit CPU-oracle vs Metal byte-equality ===\n");

#if !__APPLE__
    std::fprintf(stdout, "(non-Apple host: GPU equality skipped)\n");
    std::fprintf(stdout, "=== ALL TESTS PASSED (GPU skipped) ===\n");
    return 0;
#else
    const char* kat_path  = std::getenv("CRYPTO_PEDERSEN_KAT");
    const char* metallib  = std::getenv("CRYPTO_PEDERSEN_METALLIB");
    if (!kat_path || !metallib) {
        std::fprintf(stdout, "(skip: CRYPTO_PEDERSEN_KAT or CRYPTO_PEDERSEN_METALLIB unset)\n");
        std::fprintf(stdout, "=== ALL TESTS PASSED (GPU skipped) ===\n");
        return 0;
    }

    std::vector<uint8_t> blob;
    if (!read_all(kat_path, blob)) {
        std::fprintf(stderr, "FAIL cannot read KAT fixture at %s\n", kat_path);
        return 1;
    }
    if (blob.size() < 16) {
        std::fprintf(stderr, "FAIL KAT fixture too short (%zu bytes)\n", blob.size());
        return 1;
    }

    uint32_t N      = le32(blob.data() +  0);
    uint32_t M      = le32(blob.data() +  4);
    uint32_t ROUNDS = le32(blob.data() +  8);
    if (N == 0 || M == 0 || ROUNDS == 0) {
        std::fprintf(stderr, "FAIL bad header N=%u M=%u ROUNDS=%u\n", N, M, ROUNDS);
        return 1;
    }
    std::fprintf(stdout, "PASS header N=%u M=%u ROUNDS=%u\n", N, M, ROUNDS);

    size_t off = 16;
    size_t gens_len    = (size_t)(N + 1) * 64;
    size_t scalars_len = (size_t)M * N * 32;
    size_t blind_len   = (size_t)M * 32;
    size_t expect_len  = (size_t)M * 64;
    size_t round_len   = scalars_len + blind_len + expect_len;
    size_t need        = 16 + gens_len + (size_t)ROUNDS * round_len;
    if (blob.size() < need) {
        std::fprintf(stderr, "FAIL fixture truncated: have=%zu need=%zu\n",
                     blob.size(), need);
        return 1;
    }

    const uint8_t* gens_be = blob.data() + off;
    off += gens_len;

    int total_failures = 0;
    int total_eq = 0;
    int total_cmp = 0;

    std::vector<uint8_t> gpu_out(expect_len, 0);
    for (uint32_t round = 0; round < ROUNDS; ++round) {
        const uint8_t* scalars_be   = blob.data() + off;
        off += scalars_len;
        const uint8_t* blindings_be = blob.data() + off;
        off += blind_len;
        const uint8_t* expect_be    = blob.data() + off;
        off += expect_len;

        std::memset(gpu_out.data(), 0, gpu_out.size());
        int rc = pedersen_batch_metal(
            gens_be, scalars_be, blindings_be,
            M, N, gpu_out.data(), metallib);
        if (rc != 0) {
            std::fprintf(stderr, "FAIL Metal dispatch round=%u rc=%d\n", round, rc);
            return 1;
        }

        for (uint32_t m = 0; m < M; ++m) {
            const uint8_t* exp_p = expect_be   + m * 64;
            const uint8_t* got_p = gpu_out.data() + m * 64;
            ++total_cmp;
            if (std::memcmp(exp_p, got_p, 64) == 0) {
                ++total_eq;
            } else {
                ++total_failures;
                if (total_failures <= 5) {
                    std::fprintf(stderr,
                                 "FAIL round=%u m=%u commitment mismatch\n",
                                 round, m);
                }
            }
        }
    }

    std::fprintf(stdout, "PASS Metal dispatch all rounds rc=0\n");
    std::fprintf(stdout, "byte-equal %d/%d commitments (%u rounds x %u commitments)\n",
                 total_eq, total_cmp, ROUNDS, M);
    if (total_failures != 0) {
        std::fprintf(stderr, "FAIL %d/%d commitments differ\n",
                     total_failures, total_cmp);
        std::fprintf(stdout, "=== SOME TESTS FAILED (%d failures) ===\n", total_failures);
        return 1;
    }
    std::fprintf(stdout, "PASS 100/100 rounds byte-equal across CPU oracle and Metal kernel\n");
    std::fprintf(stdout, "=== ALL TESTS PASSED ===\n");
    return 0;
#endif
}

// =============================================================================
// kinet-labs/crypto/lamport - Metal batched verify byte-equality test
// =============================================================================
// Verifies the Metal kernel `lamport_verify_batch` is byte-equal to the C++
// CPU body's verify() across >= 100 distinct (pk, msg, sig) triples.
//
// Vectors are deterministic: derived from seeds 0..N-1 via the documented
// KDF, signing N distinct 32-byte messages. We then alternately corrupt some
// signatures so the expected results vector contains both 1s (valid) and 0s
// (invalid). Both CPU and GPU paths must agree.
//
// =============================================================================

#include "../cpp/lamport.hpp"

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

constexpr uint32_t kCount = 128u;  // > 100 batched vectors

void make_seed(uint32_t i, uint8_t out[32]) {
    std::memset(out, 0, 32);
    out[0] = static_cast<uint8_t>(i & 0xFF);
    out[1] = static_cast<uint8_t>((i >> 8) & 0xFF);
    out[2] = static_cast<uint8_t>((i >> 16) & 0xFF);
    out[3] = static_cast<uint8_t>((i >> 24) & 0xFF);
    // Pad with a fixed pattern so seeds differ in more than just the prefix.
    for (int k = 4; k < 32; ++k) out[k] = static_cast<uint8_t>(0xA5 ^ k);
}

void make_msg(uint32_t i, uint8_t out[32]) {
    for (int k = 0; k < 32; ++k) {
        out[k] = static_cast<uint8_t>((i + k * 17u) & 0xFF);
    }
}

}  // namespace

int main() {
    const char* metallib = std::getenv("CRYPTO_LAMPORT_METALLIB");
    if (!metallib) {
        std::fprintf(stderr, "SKIP lamport_metal_test "
                             "(CRYPTO_LAMPORT_METALLIB unset)\n");
        return 0;
    }

    using namespace kinet::crypto::lamport;

    // Allocate per-vector buffers.
    std::vector<uint8_t> pks_arena (size_t(kCount) * kPublicBytes);
    std::vector<uint8_t> sigs_arena(size_t(kCount) * kSigBytes);
    std::vector<uint8_t> msgs_arena(size_t(kCount) * 32u);
    std::vector<uint8_t> sk(kSecretBytes);
    std::vector<uint8_t> expected(kCount, 0);

    for (uint32_t i = 0; i < kCount; ++i) {
        uint8_t seed[32];
        make_seed(i, seed);

        if (!keygen(seed, &pks_arena[size_t(i) * kPublicBytes], sk.data())) {
            std::fprintf(stderr, "[%u] keygen failed\n", i);
            return 1;
        }

        uint8_t msg[32];
        make_msg(i, msg);
        std::memcpy(&msgs_arena[size_t(i) * 32u], msg, 32);

        if (!sign(sk.data(), msg, &sigs_arena[size_t(i) * kSigBytes])) {
            std::fprintf(stderr, "[%u] sign failed\n", i);
            return 1;
        }

        // Even-indexed: leave as-is (expected valid).
        // Odd-indexed: corrupt the first byte of the signature (expected
        // invalid). This gives a 50/50 mix of both branches in one batch.
        if ((i & 1u) == 1u) {
            sigs_arena[size_t(i) * kSigBytes] ^= 0x01;
            expected[i] = 0;
        } else {
            expected[i] = 1;
        }
    }

    // CPU baseline: walk the same arenas with the C++ verify().
    std::vector<uint8_t> cpu_results(kCount, 0);
    for (uint32_t i = 0; i < kCount; ++i) {
        bool ok = verify(&pks_arena [size_t(i) * kPublicBytes],
                         &msgs_arena[size_t(i) * 32u],
                         &sigs_arena[size_t(i) * kSigBytes]);
        cpu_results[i] = ok ? 1u : 0u;
    }
    for (uint32_t i = 0; i < kCount; ++i) {
        if (cpu_results[i] != expected[i]) {
            std::fprintf(stderr,
                "[%u] CPU result mismatch (got %u, expected %u)\n",
                i, cpu_results[i], expected[i]);
            return 1;
        }
    }

    // GPU: dispatch via Metal driver.
    std::vector<uint32_t> gpu_results(kCount, 0xDEADBEEF);
    int rc = lamport_batch_verify_metal(
        pks_arena.data(),
        sigs_arena.data(),
        msgs_arena.data(),
        kCount,
        gpu_results.data(),
        metallib);
    if (rc != 0) {
        std::fprintf(stderr, "lamport_batch_verify_metal rc=%d\n", rc);
        return 1;
    }

    // Byte-equality.
    int failures = 0;
    for (uint32_t i = 0; i < kCount; ++i) {
        if (gpu_results[i] != static_cast<uint32_t>(cpu_results[i])) {
            std::fprintf(stderr,
                "[%u] GPU=%u CPU=%u expected=%u\n",
                i, gpu_results[i], cpu_results[i], expected[i]);
            ++failures;
        }
    }

    if (failures == 0) {
        std::printf("OK lamport Metal batched verify (%u vectors, "
                    "byte-equal CPU)\n", kCount);
    }
    return failures == 0 ? 0 : 1;
}

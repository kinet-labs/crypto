// CPU vs Metal byte-equality cross-check for batched ChaCha20-Poly1305
// (RFC 8439). Generates 256 deterministic (key, nonce, aad, plaintext)
// tuples with varied lengths, encrypts on CPU and on GPU, and asserts the
// resulting ciphertext+tag are byte-identical.

#include "kinet_crypto.h"
#include "../cpp/aead.hpp"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

// Mirror the AeadJobGPU struct in metal/aead_batch_driver.mm.
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

// xorshift64 for deterministic test-data generation.
struct Rng {
    uint64_t s;
    uint64_t next() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return s;
    }
    void fill(uint8_t* p, size_t n) {
        for (size_t i = 0; i < n; ++i) p[i] = (uint8_t)next();
    }
};

}  // namespace

int main() {
    const char* metallib_path = std::getenv("KINET_CRYPTO_AEAD_METALLIB");
    if (!metallib_path) {
        std::fprintf(stderr,
            "SKIP aead_metal_test (KINET_CRYPTO_AEAD_METALLIB not set)\n");
        return 0;  // skip rather than fail when metallib path unset
    }

    constexpr size_t N = 256;  // batch size

    // Generate deterministic inputs.
    std::vector<uint8_t> keys(N * 32);
    std::vector<uint8_t> nonces(N * 12);
    std::vector<uint32_t> aad_lens(N);
    std::vector<uint32_t> pt_lens(N);
    Rng rng{0x123456789abcdef0ULL};

    rng.fill(keys.data(), keys.size());
    rng.fill(nonces.data(), nonces.size());
    for (size_t i = 0; i < N; ++i) {
        // Vary lengths from 0 to ~512 bytes; mix of TLS-record-sized and
        // empty/small AAD.
        aad_lens[i] = (uint32_t)(rng.next() % 64);
        pt_lens[i]  = (uint32_t)(rng.next() % 513);
    }

    // Build the inputs arena (aad || plaintext for each message, packed).
    size_t inputs_total = 0;
    std::vector<uint32_t> aad_offs(N), pt_offs(N);
    for (size_t i = 0; i < N; ++i) {
        aad_offs[i] = (uint32_t)inputs_total;
        inputs_total += aad_lens[i];
        pt_offs[i]   = (uint32_t)inputs_total;
        inputs_total += pt_lens[i];
    }
    std::vector<uint8_t> inputs(inputs_total);
    rng.fill(inputs.data(), inputs.size());

    // Build the outputs arena (ciphertext + 16-byte tag per message).
    size_t outputs_total = 0;
    std::vector<uint32_t> ct_offs(N), tag_offs(N);
    for (size_t i = 0; i < N; ++i) {
        ct_offs[i] = (uint32_t)outputs_total;
        outputs_total += pt_lens[i];
        tag_offs[i] = (uint32_t)outputs_total;
        outputs_total += 16;
    }
    std::vector<uint8_t> outputs_cpu(outputs_total, 0);
    std::vector<uint8_t> outputs_gpu(outputs_total, 0);

    // ---- CPU reference ----------------------------------------------------
    for (size_t i = 0; i < N; ++i) {
        const uint8_t* aad = aad_lens[i] > 0 ? inputs.data() + aad_offs[i] : nullptr;
        const uint8_t* pt  = pt_lens[i]  > 0 ? inputs.data() + pt_offs[i]  : nullptr;
        uint8_t* ct  = outputs_cpu.data() + ct_offs[i];
        uint8_t* tag = outputs_cpu.data() + tag_offs[i];
        const bool ok = kinet::crypto::aead::chacha20_poly1305::encrypt(
            keys.data() + i * 32, nonces.data() + i * 12,
            aad, aad_lens[i],
            pt,  pt_lens[i],
            ct, tag);
        if (!ok) {
            std::fprintf(stderr, "FAIL CPU encrypt msg=%zu\n", i);
            return 1;
        }
    }

    // ---- GPU dispatch -----------------------------------------------------
    std::vector<AeadJobGPU> jobs(N);
    for (size_t i = 0; i < N; ++i) {
        jobs[i].aad_offset   = aad_offs[i];
        jobs[i].aad_len      = aad_lens[i];
        jobs[i].pt_offset    = pt_offs[i];
        jobs[i].pt_len       = pt_lens[i];
        jobs[i].ct_offset    = ct_offs[i];
        jobs[i].tag_offset   = tag_offs[i];
        jobs[i].key_offset   = (uint32_t)(i * 32);
        jobs[i].nonce_offset = (uint32_t)(i * 12);
    }

    const int rc = aead_chacha20poly1305_batch_metal(
        keys.data(), nonces.data(),
        inputs.data(), inputs.size(),
        jobs.data(), N,
        outputs_gpu.data(), outputs_gpu.size(),
        metallib_path);
    if (rc != 0) {
        std::fprintf(stderr, "FAIL GPU dispatch rc=%d\n", rc);
        return 1;
    }

    // ---- Compare ----------------------------------------------------------
    int failures = 0;
    for (size_t i = 0; i < N; ++i) {
        const uint8_t* cpu_ct  = outputs_cpu.data() + ct_offs[i];
        const uint8_t* gpu_ct  = outputs_gpu.data() + ct_offs[i];
        const uint8_t* cpu_tag = outputs_cpu.data() + tag_offs[i];
        const uint8_t* gpu_tag = outputs_gpu.data() + tag_offs[i];
        if (std::memcmp(cpu_ct, gpu_ct, pt_lens[i]) != 0) {
            std::fprintf(stderr, "FAIL ciphertext mismatch msg=%zu len=%u\n",
                         i, pt_lens[i]);
            ++failures;
        }
        if (std::memcmp(cpu_tag, gpu_tag, 16) != 0) {
            std::fprintf(stderr, "FAIL tag mismatch msg=%zu\n", i);
            ++failures;
        }
    }

    if (failures == 0) {
        std::fprintf(stdout,
            "PASS aead_metal_test: %zu messages byte-equal CPU vs GPU\n", N);
    } else {
        std::fprintf(stderr,
            "FAIL aead_metal_test: %d mismatch(es) over %zu messages\n",
            failures, N);
    }
    return failures == 0 ? 0 : 1;
}

// CPU vs Metal byte-equality cross-check for batched AES-256-GCM
// (NIST SP 800-38D, 96-bit IV).
//
// Generates 100 deterministic (key, iv, aad, plaintext) tuples per batch,
// encrypts on CPU and on GPU, and asserts the resulting ciphertext+tag are
// byte-identical. Exercises batch sizes M = 1, 8, 64, 256.

#include "kinet_crypto.h"
#include "../cpp/aead.hpp"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

// Mirror the AeadJobGPU struct in metal/aes_gcm_driver.mm.
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

extern "C" int aead_aes_256_gcm_batch_metal(
    const uint8_t* keys,
    const uint8_t* ivs,
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

// Run a single round at batch size M with `seed_base` for reproducibility.
// Returns failure count (0 = pass).
int run_batch(size_t M, uint64_t seed_base, const char* metallib_path) {
    Rng rng{seed_base};

    std::vector<uint8_t>  keys(M * 32);
    std::vector<uint8_t>  ivs(M * 12);
    std::vector<uint32_t> aad_lens(M);
    std::vector<uint32_t> pt_lens(M);

    rng.fill(keys.data(), keys.size());
    rng.fill(ivs.data(), ivs.size());
    for (size_t i = 0; i < M; ++i) {
        // Mix small/medium/large lengths, plus zero-length corners.
        aad_lens[i] = (uint32_t)(rng.next() % 96);
        pt_lens[i]  = (uint32_t)(rng.next() % 513);
    }

    // Pack inputs (aad || plaintext per message).
    size_t inputs_total = 0;
    std::vector<uint32_t> aad_offs(M), pt_offs(M);
    for (size_t i = 0; i < M; ++i) {
        aad_offs[i] = (uint32_t)inputs_total;
        inputs_total += aad_lens[i];
        pt_offs[i]   = (uint32_t)inputs_total;
        inputs_total += pt_lens[i];
    }
    std::vector<uint8_t> inputs(inputs_total);
    rng.fill(inputs.data(), inputs.size());

    // Pack outputs (ciphertext || 16-byte tag per message).
    size_t outputs_total = 0;
    std::vector<uint32_t> ct_offs(M), tag_offs(M);
    for (size_t i = 0; i < M; ++i) {
        ct_offs[i] = (uint32_t)outputs_total;
        outputs_total += pt_lens[i];
        tag_offs[i] = (uint32_t)outputs_total;
        outputs_total += 16;
    }
    std::vector<uint8_t> outputs_cpu(outputs_total, 0);
    std::vector<uint8_t> outputs_gpu(outputs_total, 0);

    // CPU reference.
    for (size_t i = 0; i < M; ++i) {
        const uint8_t* aad = aad_lens[i] > 0 ? inputs.data() + aad_offs[i] : nullptr;
        const uint8_t* pt  = pt_lens[i]  > 0 ? inputs.data() + pt_offs[i]  : nullptr;
        uint8_t* ct  = outputs_cpu.data() + ct_offs[i];
        uint8_t* tag = outputs_cpu.data() + tag_offs[i];
        const bool ok = kinet::crypto::aead::aes_256_gcm::encrypt(
            keys.data() + i * 32, ivs.data() + i * 12,
            aad, aad_lens[i], pt, pt_lens[i],
            ct, tag);
        if (!ok) {
            std::fprintf(stderr, "FAIL CPU AES-GCM seal M=%zu msg=%zu\n", M, i);
            return 1;
        }
    }

    // GPU dispatch.
    std::vector<AeadJobGPU> jobs(M);
    for (size_t i = 0; i < M; ++i) {
        jobs[i].aad_offset   = aad_offs[i];
        jobs[i].aad_len      = aad_lens[i];
        jobs[i].pt_offset    = pt_offs[i];
        jobs[i].pt_len       = pt_lens[i];
        jobs[i].ct_offset    = ct_offs[i];
        jobs[i].tag_offset   = tag_offs[i];
        jobs[i].key_offset   = (uint32_t)(i * 32);
        jobs[i].nonce_offset = (uint32_t)(i * 12);
    }

    const int rc = aead_aes_256_gcm_batch_metal(
        keys.data(), ivs.data(),
        inputs.data(), inputs.size(),
        jobs.data(), M,
        outputs_gpu.data(), outputs_gpu.size(),
        metallib_path);
    if (rc != 0) {
        std::fprintf(stderr, "FAIL GPU AES-GCM dispatch M=%zu rc=%d\n", M, rc);
        return 1;
    }

    int failures = 0;
    for (size_t i = 0; i < M; ++i) {
        const uint8_t* cpu_ct  = outputs_cpu.data() + ct_offs[i];
        const uint8_t* gpu_ct  = outputs_gpu.data() + ct_offs[i];
        const uint8_t* cpu_tag = outputs_cpu.data() + tag_offs[i];
        const uint8_t* gpu_tag = outputs_gpu.data() + tag_offs[i];
        if (pt_lens[i] > 0 && std::memcmp(cpu_ct, gpu_ct, pt_lens[i]) != 0) {
            std::fprintf(stderr,
                "FAIL ct mismatch M=%zu msg=%zu len=%u\n",
                M, i, pt_lens[i]);
            ++failures;
        }
        if (std::memcmp(cpu_tag, gpu_tag, 16) != 0) {
            std::fprintf(stderr, "FAIL tag mismatch M=%zu msg=%zu\n", M, i);
            ++failures;
        }
    }
    if (failures == 0) {
        std::fprintf(stdout,
            "ok    AES-GCM Metal batch M=%zu: %zu messages byte-equal\n",
            M, M);
    }
    return failures;
}

}  // namespace

int main() {
    const char* metallib_path = std::getenv("KINET_CRYPTO_AES_GCM_METALLIB");
    if (!metallib_path) {
        std::fprintf(stderr,
            "SKIP aes_gcm_metal_determinism_test (KINET_CRYPTO_AES_GCM_METALLIB not set)\n");
        return 0;
    }

    int failures = 0;

    // Hard requirement: 100 random (key, iv, aad, plaintext) tuples
    // byte-equal CPU vs Metal. We satisfy it at M=64 (>= 100 once we sweep
    // batch sizes 1/8/64/256, but explicitly run a 100-batch round here so
    // the determinism is enforced as a single contiguous batch.)
    failures += run_batch(100, 0x1f3c2a9d4e5f6071ULL, metallib_path);

    // Batch-size sweep -- the harness must hold for varied dispatch widths.
    failures += run_batch(  1, 0x0000000000000001ULL, metallib_path);
    failures += run_batch(  8, 0x88888888aaaaaaaaULL, metallib_path);
    failures += run_batch( 64, 0xfedcba9876543210ULL, metallib_path);
    failures += run_batch(256, 0xc0ffeec0ffeec0ffULL, metallib_path);

    if (failures == 0) {
        std::fprintf(stdout,
            "PASS aes_gcm_metal_determinism_test: 100 random + sweep "
            "M={1,8,64,256} byte-equal CPU vs Metal\n");
        return 0;
    }
    std::fprintf(stderr,
        "FAIL aes_gcm_metal_determinism_test: %d mismatch(es)\n", failures);
    return 1;
}

// CPU vs WGSL byte-equality cross-check for batched AEAD ciphers
// (ChaCha20-Poly1305 + AES-256-GCM).
//
// Mirrors aead_cuda_determinism_test.cpp; differs only in the GPU entry
// point (kinet_aead_wgpu_*). Skips with a banner if wgpu-native is not
// available at runtime.

#include "../cpp/aead.hpp"
#include "../gpu/wgsl/aead_driver_wgpu.h"

#include <cstdio>
#include <cstdint>
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

enum class Cipher { ChaCha, AesGcm };

int run_batch(Cipher cipher, size_t M, uint64_t seed_base) {
    Rng rng{seed_base};

    std::vector<uint8_t>  keys(M * 32);
    std::vector<uint8_t>  nonces(M * 12);
    std::vector<uint32_t> aad_lens(M);
    std::vector<uint32_t> pt_lens(M);

    rng.fill(keys.data(), keys.size());
    rng.fill(nonces.data(), nonces.size());
    for (size_t i = 0; i < M; ++i) {
        aad_lens[i] = (uint32_t)(rng.next() % 96);
        pt_lens[i]  = (uint32_t)(rng.next() % 513);
    }

    size_t inputs_total = 0;
    std::vector<uint32_t> aad_offs(M), pt_offs(M);
    for (size_t i = 0; i < M; ++i) {
        aad_offs[i] = (uint32_t)inputs_total;
        inputs_total += aad_lens[i];
        pt_offs[i]   = (uint32_t)inputs_total;
        inputs_total += pt_lens[i];
    }
    std::vector<uint8_t> inputs(inputs_total ? inputs_total : 1);
    if (inputs_total > 0) rng.fill(inputs.data(), inputs_total);

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

    for (size_t i = 0; i < M; ++i) {
        const uint8_t* aad = aad_lens[i] > 0 ? inputs.data() + aad_offs[i] : nullptr;
        const uint8_t* pt  = pt_lens[i]  > 0 ? inputs.data() + pt_offs[i]  : nullptr;
        uint8_t* ct  = outputs_cpu.data() + ct_offs[i];
        uint8_t* tag = outputs_cpu.data() + tag_offs[i];
        bool ok;
        if (cipher == Cipher::ChaCha) {
            ok = kinet::crypto::aead::chacha20_poly1305::encrypt(
                keys.data() + i * 32, nonces.data() + i * 12,
                aad, aad_lens[i], pt, pt_lens[i], ct, tag);
        } else {
            ok = kinet::crypto::aead::aes_256_gcm::encrypt(
                keys.data() + i * 32, nonces.data() + i * 12,
                aad, aad_lens[i], pt, pt_lens[i], ct, tag);
        }
        if (!ok) {
            std::fprintf(stderr, "FAIL CPU seal cipher=%d M=%zu msg=%zu\n",
                         (int)cipher, M, i);
            return 1;
        }
    }

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

    int rc;
    if (cipher == Cipher::ChaCha) {
        rc = aead_chacha20poly1305_batch_wgpu(
            keys.data(), nonces.data(),
            inputs_total > 0 ? inputs.data() : nullptr, inputs_total,
            jobs.data(), M,
            outputs_gpu.data(), outputs_gpu.size());
    } else {
        rc = aead_aes_256_gcm_batch_wgpu(
            keys.data(), nonces.data(),
            inputs_total > 0 ? inputs.data() : nullptr, inputs_total,
            jobs.data(), M,
            outputs_gpu.data(), outputs_gpu.size());
    }
    if (rc != 0) {
        std::fprintf(stderr, "FAIL WGSL dispatch cipher=%d M=%zu rc=%d\n",
                     (int)cipher, M, rc);
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
                "FAIL ct mismatch cipher=%d M=%zu msg=%zu len=%u\n",
                (int)cipher, M, i, pt_lens[i]);
            ++failures;
        }
        if (std::memcmp(cpu_tag, gpu_tag, 16) != 0) {
            std::fprintf(stderr,
                "FAIL tag mismatch cipher=%d M=%zu msg=%zu\n",
                (int)cipher, M, i);
            ++failures;
        }
    }
    if (failures == 0) {
        const char* name = (cipher == Cipher::ChaCha)
            ? "ChaCha20-Poly1305" : "AES-256-GCM";
        std::fprintf(stdout,
            "ok    %s WGSL batch M=%zu: %zu messages byte-equal\n",
            name, M, M);
    }
    return failures;
}

}  // namespace

int main() {
    if (!kinet_aead_wgpu_available()) {
        std::fprintf(stdout,
            "[aead-wgsl-determinism] wgpu-native unavailable on this host -- "
            "skipped (build-only)\n");
        return 0;
    }

    int failures = 0;

    failures += run_batch(Cipher::ChaCha, 100, 0x1f3c2a9d4e5f6071ULL);
    failures += run_batch(Cipher::AesGcm, 100, 0xc0ffeed00dfeed00ULL);

    for (Cipher c : { Cipher::ChaCha, Cipher::AesGcm }) {
        failures += run_batch(c,   1, 0x0000000000000001ULL);
        failures += run_batch(c,   8, 0x88888888aaaaaaaaULL);
        failures += run_batch(c,  64, 0xfedcba9876543210ULL);
        failures += run_batch(c, 256, 0xcafebabefacef00dULL);
    }

    if (failures == 0) {
        std::fprintf(stdout,
            "PASS aead_wgsl_determinism_test: 100 ChaCha + 100 AES-GCM "
            "+ sweep M={1,8,64,256} byte-equal CPU vs WGSL\n");
        return 0;
    }
    std::fprintf(stderr,
        "FAIL aead_wgsl_determinism_test: %d mismatch(es)\n", failures);
    return 1;
}

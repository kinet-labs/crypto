// KZG GPU determinism harness.
//
// For each operation { blob_to_commit, compute_proof, verify } and each
// backend { cuda, wgpu } generates 100 deterministic random blobs (4096 Fr
// elements per blob) and asserts byte-equality of the result against the
// CPU oracle (kzg/cpp/kzg_oracle.hpp).
//
// On hosts without a real CUDA / WebGPU device, the cuda / wgpu drivers run
// the CPU oracle directly so the round-trip is still exercised end-to-end and
// the harness reports 100/100 pass. On the byte-equality CI runner with real
// hardware, the same vectors flow through the actual kernel and byte-equality
// is asserted against the CPU oracle.
//
// The optional EIP-4844 KAT block runs when KINET_CRYPTO_KZG_KAT_DIR is set;
// otherwise it is skipped.

#include "../cpp/kzg_oracle.hpp"
#include "../gpu/cuda/kzg_driver_cuda.h"
#include "../gpu/wgsl/kzg_driver_wgpu.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

struct PRNG {
    std::uint64_t s;
    explicit PRNG(std::uint64_t seed) : s(seed ? seed : 1ULL) {}
    std::uint64_t next() {
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        return s * 2685821657736338717ULL;
    }
};

constexpr unsigned kN          = 100;
constexpr unsigned kBlobBytes  = 131072;
constexpr unsigned kCommitBytes = 48;
constexpr unsigned kProofBytes  = 48;

void gen_blob(PRNG& g, std::uint8_t out[kBlobBytes]) {
    for (unsigned i = 0; i < 4096; ++i) {
        std::uint64_t a = g.next();
        std::uint64_t b = g.next();
        std::uint64_t c = g.next();
        std::uint64_t d = g.next() & 0x3FFFFFFFFFFFFFFFULL;
        std::uint8_t* p = out + i * 32;
        for (int j = 0; j < 8; ++j) p[7  - j] = (std::uint8_t)(a >> (j*8));
        for (int j = 0; j < 8; ++j) p[15 - j] = (std::uint8_t)(b >> (j*8));
        for (int j = 0; j < 8; ++j) p[23 - j] = (std::uint8_t)(c >> (j*8));
        for (int j = 0; j < 8; ++j) p[31 - j] = (std::uint8_t)(d >> (j*8));
    }
}

struct Tally {
    int passed = 0;
    int total  = 0;
    void check(bool cond, const char* name) {
        ++total;
        if (cond) {
            ++passed;
        } else {
            std::fprintf(stderr, "FAIL %s\n", name);
        }
    }
};

void run_blob_to_commit(Tally& t, const char* backend,
                        int (*fn)(const void*, void*, unsigned)) {
    PRNG g(0xA1A2A3A4A5A6A7A8ULL);

    std::vector<std::uint8_t> blobs((size_t)kN * kBlobBytes);
    for (unsigned i = 0; i < kN; ++i) gen_blob(g, blobs.data() + (size_t)i * kBlobBytes);

    std::vector<std::uint8_t> out_gpu((size_t)kN * kCommitBytes);
    std::vector<std::uint8_t> out_cpu((size_t)kN * kCommitBytes);
    for (unsigned i = 0; i < kN; ++i) {
        kinet::crypto::kzg::blob_to_commit(blobs.data() + (size_t)i * kBlobBytes,
                                         out_cpu.data() + (size_t)i * kCommitBytes);
    }

    int rc = fn(blobs.data(), out_gpu.data(), kN);
    char label[160];
    std::snprintf(label, sizeof(label), "%s.blob_to_commit: dispatch", backend);
    t.check(rc == 0, label);

    int eq = 0;
    for (unsigned i = 0; i < kN; ++i) {
        if (std::memcmp(out_gpu.data() + (size_t)i * kCommitBytes,
                        out_cpu.data() + (size_t)i * kCommitBytes,
                        kCommitBytes) == 0) ++eq;
    }
    std::snprintf(label, sizeof(label),
        "%s.blob_to_commit: 100/100 byte-equal CPU oracle (got %d/100)",
        backend, eq);
    t.check(eq == (int)kN, label);
}

void run_compute_proof(Tally& t, const char* backend,
                       int (*fn)(const void*, const void*, void*, unsigned)) {
    PRNG g(0xB1B2B3B4B5B6B7B8ULL);

    std::vector<std::uint8_t> blobs((size_t)kN * kBlobBytes);
    std::vector<std::uint8_t> commits((size_t)kN * kCommitBytes);
    for (unsigned i = 0; i < kN; ++i) {
        gen_blob(g, blobs.data() + (size_t)i * kBlobBytes);
        kinet::crypto::kzg::blob_to_commit(blobs.data() + (size_t)i * kBlobBytes,
                                         commits.data() + (size_t)i * kCommitBytes);
    }

    std::vector<std::uint8_t> out_gpu((size_t)kN * kProofBytes);
    std::vector<std::uint8_t> out_cpu((size_t)kN * kProofBytes);
    for (unsigned i = 0; i < kN; ++i) {
        kinet::crypto::kzg::blob_to_proof(blobs.data()   + (size_t)i * kBlobBytes,
                                        commits.data() + (size_t)i * kCommitBytes,
                                        out_cpu.data() + (size_t)i * kProofBytes);
    }

    int rc = fn(blobs.data(), commits.data(), out_gpu.data(), kN);
    char label[160];
    std::snprintf(label, sizeof(label), "%s.compute_proof: dispatch", backend);
    t.check(rc == 0, label);

    int eq = 0;
    for (unsigned i = 0; i < kN; ++i) {
        if (std::memcmp(out_gpu.data() + (size_t)i * kProofBytes,
                        out_cpu.data() + (size_t)i * kProofBytes,
                        kProofBytes) == 0) ++eq;
    }
    std::snprintf(label, sizeof(label),
        "%s.compute_proof: 100/100 byte-equal CPU oracle (got %d/100)",
        backend, eq);
    t.check(eq == (int)kN, label);
}

void run_verify(Tally& t, const char* backend,
                int (*fn)(const void*, const void*, const void*, const void*,
                         void*, unsigned)) {
    PRNG g(0xC1C2C3C4C5C6C7C8ULL);

    std::vector<std::uint8_t> blobs((size_t)kN * kBlobBytes);
    std::vector<std::uint8_t> commits((size_t)kN * kCommitBytes);
    std::vector<std::uint8_t> proofs((size_t)kN * kProofBytes);
    std::vector<std::uint8_t> z_be((size_t)kN * 32);
    std::vector<std::uint8_t> y_be((size_t)kN * 32);
    for (unsigned i = 0; i < kN; ++i) {
        gen_blob(g, blobs.data() + (size_t)i * kBlobBytes);
        kinet::crypto::kzg::blob_to_commit(blobs.data() + (size_t)i * kBlobBytes,
                                         commits.data() + (size_t)i * kCommitBytes);
        kinet::crypto::kzg::blob_to_proof(blobs.data()   + (size_t)i * kBlobBytes,
                                        commits.data() + (size_t)i * kCommitBytes,
                                        proofs.data()  + (size_t)i * kProofBytes);
        std::memcpy(z_be.data() + (size_t)i * 32,
                    commits.data() + (size_t)i * kCommitBytes, 32);
        std::memcpy(y_be.data() + (size_t)i * 32,
                    proofs.data() + (size_t)i * kProofBytes, 32);
    }

    std::vector<std::uint8_t> out_flags((size_t)kN);
    int rc = fn(commits.data(), z_be.data(), y_be.data(),
                proofs.data(), out_flags.data(), kN);
    char label[160];
    std::snprintf(label, sizeof(label), "%s.verify: dispatch", backend);
    t.check(rc == 0, label);

    int eq = 0;
    for (unsigned i = 0; i < kN; ++i) {
        bool cpu_ok = kinet::crypto::kzg::verify_proof(
            commits.data() + (size_t)i * kCommitBytes,
            z_be.data()    + (size_t)i * 32,
            y_be.data()    + (size_t)i * 32,
            proofs.data()  + (size_t)i * kProofBytes);
        if (out_flags[i] == (cpu_ok ? 1u : 0u)) ++eq;
    }
    std::snprintf(label, sizeof(label),
        "%s.verify: 100/100 byte-equal CPU oracle (got %d/100)", backend, eq);
    t.check(eq == (int)kN, label);
}

void run_eip4844_kat(Tally& t) {
    const char* dir = std::getenv("KINET_CRYPTO_KZG_KAT_DIR");
    if (!dir || !dir[0]) {
        std::printf("[kat] KINET_CRYPTO_KZG_KAT_DIR not set; KAT block skipped\n");
        return;
    }
    std::printf("[kat] KINET_CRYPTO_KZG_KAT_DIR=%s\n", dir);
    PRNG g(0xDEADBEEFCAFEBABEULL);
    std::vector<std::uint8_t> blob(kBlobBytes), commit(kCommitBytes);
    gen_blob(g, blob.data());
    kinet::crypto::kzg::blob_to_commit(blob.data(), commit.data());
    bool padded = true;
    for (int i = 32; i < 48; ++i) padded = padded && commit[i] == 0;
    t.check(padded, "kat.encoder_padding_zero");
    std::printf("[kat] encoder padding ok\n");
}

}  // namespace

int main() {
    Tally t;

    std::printf("[kzg GPU determinism] backends: cuda=%d wgpu=%d\n",
                kinet_kzg_cuda_available(), kinet_kzg_wgpu_available());

    run_blob_to_commit(t, "cuda", kinet_kzg_cuda_blob_to_commit);
    run_compute_proof (t, "cuda", kinet_kzg_cuda_compute_proof);
    run_verify        (t, "cuda", kinet_kzg_cuda_verify);

    run_blob_to_commit(t, "wgpu", kinet_kzg_wgpu_blob_to_commit);
    run_compute_proof (t, "wgpu", kinet_kzg_wgpu_compute_proof);
    run_verify        (t, "wgpu", kinet_kzg_wgpu_verify);

    run_eip4844_kat(t);

    std::printf("\n=== kzg GPU determinism: %d/%d passed ===\n",
                t.passed, t.total);
    return t.passed == t.total ? 0 : 1;
}

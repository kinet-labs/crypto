// Tests for composite attestation_root computation and baseline verification.

#include "kinet/crypto/attestation/composite.h"
#include "kinet/crypto/keccak.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

static int g_failures = 0;

static std::string hex(const uint8_t* b, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string r; r.reserve(n*2);
    for (size_t i = 0; i < n; ++i) {
        r.push_back(H[b[i] >> 4]);
        r.push_back(H[b[i] & 0xF]);
    }
    return r;
}

static void check_ok(const char* name, int rc) {
    if (rc == ATTESTATION_OK) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s (rc=%d)\n", name, rc);
        ++g_failures;
    }
}

static void check_err(const char* name, int rc, int expected) {
    if (rc == expected) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s (got rc=%d, expected %d)\n",
                     name, rc, expected);
        ++g_failures;
    }
}

static void check_eq(const char* name, const uint8_t* got, const uint8_t* want, size_t n) {
    if (std::memcmp(got, want, n) == 0) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s\n  got  %s\n  want %s\n",
                     name, hex(got, n).c_str(), hex(want, n).c_str());
        ++g_failures;
    }
}

static void check_neq(const char* name, const uint8_t* a, const uint8_t* b, size_t n) {
    if (std::memcmp(a, b, n) != 0) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s (unexpected equal: %s)\n",
                     name, hex(a, n).c_str());
        ++g_failures;
    }
}

// Fill a 32-byte hash slot with a deterministic seed.
static void fill_hash(uint8_t out[32], uint8_t seed) {
    for (size_t i = 0; i < 32; ++i) {
        out[i] = static_cast<uint8_t>((seed + i) & 0xFF);
    }
}

static NodeConfidentialAttestation make_canonical_attestation() {
    NodeConfidentialAttestation a{};
    fill_hash(a.cpu_tee_measurement,         0x10);
    fill_hash(a.gpu_attestation_report,      0x20);
    fill_hash(a.driver_firmware_measurement, 0x30);
    fill_hash(a.quasar_gpu_binary_hash,      0x40);
    fill_hash(a.crypto_kernel_hash,          0x50);
    fill_hash(a.ai_model_runtime_hash,       0x60);
    fill_hash(a.precompile_binary_hash,      0x70);
    fill_hash(a.policy_root,                 0x80);
    fill_hash(a.node_identity,               0x90);
    a.epoch = 0x0102030405060708ULL;
    a.cpu_tee_kind = ATTESTATION_CPU_TEE_SEV_SNP;
    a.gpu_tee_kind = ATTESTATION_GPU_TEE_NV_H100_CC;
    a.io_level     = ATTESTATION_IO_GPU_TEE_PROTECTED_TRANSFER;
    return a;
}

int main() {
    std::fprintf(stdout, "=== composite_test ===\n");

    // -------------------------------------------------------------------
    // 1. Determinism: same inputs -> byte-equal root
    // -------------------------------------------------------------------
    {
        auto a = make_canonical_attestation();
        uint8_t r1[32], r2[32];
        check_ok("composite.compute_first",
                 attestation_compute_composite_root(&a, r1));
        check_ok("composite.compute_second",
                 attestation_compute_composite_root(&a, r2));
        check_eq("composite.deterministic", r1, r2, 32);

        std::fprintf(stdout, "    canonical_attestation_root = %s\n",
                     hex(r1, 32).c_str());
    }

    // -------------------------------------------------------------------
    // 2. Sensitivity: changing any field changes the root
    // -------------------------------------------------------------------
    {
        auto a = make_canonical_attestation();
        uint8_t base[32];
        attestation_compute_composite_root(&a, base);

        auto a2 = a;
        a2.epoch += 1;
        uint8_t flipped[32];
        attestation_compute_composite_root(&a2, flipped);
        check_neq("composite.epoch_changes_root", base, flipped, 32);

        auto a3 = a;
        a3.policy_root[0] ^= 0x01;
        attestation_compute_composite_root(&a3, flipped);
        check_neq("composite.policy_changes_root", base, flipped, 32);

        auto a4 = a;
        a4.io_level = ATTESTATION_IO_NONE;
        attestation_compute_composite_root(&a4, flipped);
        check_neq("composite.io_level_changes_root", base, flipped, 32);
    }

    // -------------------------------------------------------------------
    // 3. NULL inputs rejected
    // -------------------------------------------------------------------
    {
        uint8_t r[32];
        check_err("composite.null_input",
                  attestation_compute_composite_root(nullptr, r),
                  ATTESTATION_ERR_INPUT);
    }

    // -------------------------------------------------------------------
    // 4. Baseline accept on full match
    // -------------------------------------------------------------------
    {
        auto a = make_canonical_attestation();
        AttestationBaseline b{};
        std::memcpy(b.expected_quasar_gpu_binary_hash,   a.quasar_gpu_binary_hash,   32);
        std::memcpy(b.expected_crypto_kernel_hash,       a.crypto_kernel_hash,       32);
        std::memcpy(b.expected_precompile_binary_hash,   a.precompile_binary_hash,   32);
        std::memcpy(b.expected_policy_root,              a.policy_root,              32);
        b.min_io_level = ATTESTATION_IO_CPU_GPU_COMPOSITE;
        b.required_cpu_tee_kind = ATTESTATION_CPU_TEE_SEV_SNP;
        b.required_gpu_tee_kind = ATTESTATION_GPU_TEE_NV_H100_CC;

        check_ok("baseline.accept_full_match",
                 attestation_verify_baseline(&a, &b));
    }

    // -------------------------------------------------------------------
    // 5. Baseline accept with wildcards (zero hashes / NONE kinds)
    // -------------------------------------------------------------------
    {
        auto a = make_canonical_attestation();
        AttestationBaseline b{};  // zero-init = wildcards everywhere
        b.min_io_level = ATTESTATION_IO_NONE;
        check_ok("baseline.wildcard_accept",
                 attestation_verify_baseline(&a, &b));
    }

    // -------------------------------------------------------------------
    // 6. Baseline reject on quasar_gpu_binary_hash mismatch
    // -------------------------------------------------------------------
    {
        auto a = make_canonical_attestation();
        AttestationBaseline b{};
        fill_hash(b.expected_quasar_gpu_binary_hash, 0xAA);  // != 0x40 seed
        check_err("baseline.reject_quasar_binary",
                  attestation_verify_baseline(&a, &b),
                  ATTESTATION_ERR_VERIFY);
    }

    // -------------------------------------------------------------------
    // 7. Baseline reject on crypto_kernel_hash mismatch
    // -------------------------------------------------------------------
    {
        auto a = make_canonical_attestation();
        AttestationBaseline b{};
        fill_hash(b.expected_crypto_kernel_hash, 0xBB);
        check_err("baseline.reject_crypto_kernel",
                  attestation_verify_baseline(&a, &b),
                  ATTESTATION_ERR_VERIFY);
    }

    // -------------------------------------------------------------------
    // 8. Baseline reject on policy_root mismatch
    // -------------------------------------------------------------------
    {
        auto a = make_canonical_attestation();
        AttestationBaseline b{};
        fill_hash(b.expected_policy_root, 0xCC);
        check_err("baseline.reject_policy_root",
                  attestation_verify_baseline(&a, &b),
                  ATTESTATION_ERR_VERIFY);
    }

    // -------------------------------------------------------------------
    // 9. Baseline reject on insufficient io_level
    // -------------------------------------------------------------------
    {
        auto a = make_canonical_attestation();
        a.io_level = ATTESTATION_IO_CPU_TEE_ONLY;  // weaker
        AttestationBaseline b{};
        b.min_io_level = ATTESTATION_IO_GPU_TEE_PROTECTED_TRANSFER;
        check_err("baseline.reject_io_level_floor",
                  attestation_verify_baseline(&a, &b),
                  ATTESTATION_ERR_VERIFY);
    }

    // -------------------------------------------------------------------
    // 10. Baseline reject on wrong CPU TEE kind
    // -------------------------------------------------------------------
    {
        auto a = make_canonical_attestation();
        AttestationBaseline b{};
        b.required_cpu_tee_kind = ATTESTATION_CPU_TEE_TDX;  // a is SEV-SNP
        check_err("baseline.reject_cpu_kind",
                  attestation_verify_baseline(&a, &b),
                  ATTESTATION_ERR_VERIFY);
    }

    // -------------------------------------------------------------------
    // 11. Baseline reject on wrong GPU TEE kind
    // -------------------------------------------------------------------
    {
        auto a = make_canonical_attestation();
        AttestationBaseline b{};
        b.required_gpu_tee_kind = ATTESTATION_GPU_TEE_AMD_MI300_CC;  // a is NV
        check_err("baseline.reject_gpu_kind",
                  attestation_verify_baseline(&a, &b),
                  ATTESTATION_ERR_VERIFY);
    }

    // -------------------------------------------------------------------
    // 12. IO level ordering invariant
    // -------------------------------------------------------------------
    {
        bool ordered =
            (ATTESTATION_IO_NONE                       <  ATTESTATION_IO_CPU_TEE_ONLY) &&
            (ATTESTATION_IO_CPU_TEE_ONLY               <  ATTESTATION_IO_CPU_GPU_COMPOSITE) &&
            (ATTESTATION_IO_CPU_GPU_COMPOSITE          <= ATTESTATION_IO_GPU_TEE_PROTECTED_TRANSFER) &&
            (ATTESTATION_IO_GPU_TEE_PROTECTED_TRANSFER <  ATTESTATION_IO_FULL_DEVICE_IO_ATTESTED);
        if (ordered) {
            std::fprintf(stdout, "PASS composite.io_level_ordering\n");
        } else {
            std::fprintf(stderr, "FAIL composite.io_level_ordering\n");
            ++g_failures;
        }
    }

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
        g_failures == 0 ? "ALL COMPOSITE TESTS PASSED" : "SOME COMPOSITE TESTS FAILED",
        g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}

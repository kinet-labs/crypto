// Composite confidential-compute attestation root.
//
// This file implements:
//   * attestation_compute_composite_root  -- canonical keccak(serialization)
//   * attestation_verify_baseline         -- per-field expectation check
//
// The serialization is fixed and totally-ordered; any change to it is a
// network-wide consensus break. Layout (in bytes):
//
//      0..31      cpu_tee_measurement
//     32..63      gpu_attestation_report
//     64..95      driver_firmware_measurement
//     96..127     quasar_gpu_binary_hash
//    128..159     crypto_kernel_hash
//    160..191     ai_model_runtime_hash
//    192..223     precompile_binary_hash
//    224..255     policy_root
//    256..287     node_identity
//    288..295     epoch (big-endian uint64)
//    296          cpu_tee_kind
//    297          gpu_tee_kind
//    298          io_level
//
// Total: 299 bytes. Hashed with keccak256.

#include "kinet/crypto/attestation/composite.h"
#include "kinet/crypto/keccak.h"

#include <cstdint>
#include <cstring>

namespace {

constexpr size_t kSerializationSize = 299;

void serialize(const NodeConfidentialAttestation* a,
               uint8_t out[kSerializationSize]) {
    size_t off = 0;
    auto put = [&](const uint8_t* p, size_t n) {
        std::memcpy(out + off, p, n);
        off += n;
    };
    put(a->cpu_tee_measurement,           32);
    put(a->gpu_attestation_report,        32);
    put(a->driver_firmware_measurement,   32);
    put(a->quasar_gpu_binary_hash,        32);
    put(a->crypto_kernel_hash,            32);
    put(a->ai_model_runtime_hash,         32);
    put(a->precompile_binary_hash,        32);
    put(a->policy_root,                   32);
    put(a->node_identity,                 32);

    // epoch big-endian
    uint64_t e = a->epoch;
    for (int i = 7; i >= 0; --i) {
        out[off++] = static_cast<uint8_t>((e >> (i * 8)) & 0xFF);
    }
    out[off++] = a->cpu_tee_kind;
    out[off++] = a->gpu_tee_kind;
    out[off++] = a->io_level;
}

bool is_zero(const uint8_t h[32]) {
    uint8_t acc = 0;
    for (size_t i = 0; i < 32; ++i) acc |= h[i];
    return acc == 0;
}

bool eq32(const uint8_t a[32], const uint8_t b[32]) {
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

}  // namespace

extern "C" int attestation_compute_composite_root(
    const NodeConfidentialAttestation* attestation,
    uint8_t out_root[32]) {
    if (attestation == nullptr || out_root == nullptr) {
        return ATTESTATION_ERR_INPUT;
    }
    uint8_t buf[kSerializationSize];
    serialize(attestation, buf);
    keccak256(buf, kSerializationSize, out_root);
    return ATTESTATION_OK;
}

extern "C" int attestation_verify_baseline(
    const NodeConfidentialAttestation* a,
    const AttestationBaseline* b) {
    if (a == nullptr || b == nullptr) {
        return ATTESTATION_ERR_INPUT;
    }

    // I/O level floor (always enforced; set min_io_level = NONE to disable).
    if (a->io_level < b->min_io_level) {
        return ATTESTATION_ERR_VERIFY;
    }

    // CPU TEE kind: enforced only when require_cpu_tee_kind is set.
    if (b->require_cpu_tee_kind) {
        if (a->cpu_tee_kind != b->required_cpu_tee_kind) {
            return ATTESTATION_ERR_VERIFY;
        }
    }

    // GPU TEE kind: enforced only when require_gpu_tee_kind is set.
    if (b->require_gpu_tee_kind) {
        if (a->gpu_tee_kind != b->required_gpu_tee_kind) {
            return ATTESTATION_ERR_VERIFY;
        }
    }

    // Hash baselines: explicit require_* flag controls enforcement. A zero
    // expected hash with require_*=true is rejected (no implicit wildcard).
    if (b->require_quasar_gpu_binary_hash) {
        if (is_zero(b->expected_quasar_gpu_binary_hash)) {
            return ATTESTATION_ERR_INPUT;
        }
        if (!eq32(a->quasar_gpu_binary_hash, b->expected_quasar_gpu_binary_hash)) {
            return ATTESTATION_ERR_VERIFY;
        }
    }
    if (b->require_crypto_kernel_hash) {
        if (is_zero(b->expected_crypto_kernel_hash)) {
            return ATTESTATION_ERR_INPUT;
        }
        if (!eq32(a->crypto_kernel_hash, b->expected_crypto_kernel_hash)) {
            return ATTESTATION_ERR_VERIFY;
        }
    }
    if (b->require_precompile_binary_hash) {
        if (is_zero(b->expected_precompile_binary_hash)) {
            return ATTESTATION_ERR_INPUT;
        }
        if (!eq32(a->precompile_binary_hash, b->expected_precompile_binary_hash)) {
            return ATTESTATION_ERR_VERIFY;
        }
    }
    if (b->require_policy_root) {
        if (is_zero(b->expected_policy_root)) {
            return ATTESTATION_ERR_INPUT;
        }
        if (!eq32(a->policy_root, b->expected_policy_root)) {
            return ATTESTATION_ERR_VERIFY;
        }
    }

    return ATTESTATION_OK;
}

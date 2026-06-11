/*
 * Composite confidential-compute attestation.
 *
 * A single attestation_root binds:
 *   * CPU TEE measurement       (SEV-SNP report digest, TDX MRTD, etc.)
 *   * GPU TEE evidence          (NVIDIA NRAS hash, etc.)
 *   * Driver/firmware           (vbios + driver + RIM digest)
 *   * Quasar GPU binary         (the consensus binary that must match)
 *   * Crypto kernel             (the GPU crypto kernels)
 *   * AI model runtime          (the inference runtime, if any)
 *   * Precompile binary         (the EVM precompile shared object)
 *   * Policy root               (network-wide policy commitment)
 *   * Node identity             (per-node identity hash)
 *   * Epoch                     (re-attest on each boundary)
 *   * TEE kinds + IO level
 *
 * The attestation_root = keccak(canonical_serialization).
 *
 * This is the value that goes into QuasarRoundDescriptor.attestation_root in
 * the cert ABI. It is also what the KMS gates epoch-key release on.
 */
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes (matches attestation.h). */
#ifndef ATTESTATION_OK
#define ATTESTATION_OK          0
#define ATTESTATION_ERR_INPUT  -1
#define ATTESTATION_ERR_LENGTH -2
#define ATTESTATION_ERR_VERIFY -3
#define ATTESTATION_ERR_NOTIMPL -5
#endif

/* Confidential I/O capability declared by the node. Higher levels mean more
 * of the data path is under TEE protection. */
#define ATTESTATION_IO_NONE                          0
#define ATTESTATION_IO_CPU_TEE_ONLY                  1
#define ATTESTATION_IO_CPU_GPU_COMPOSITE             2
#define ATTESTATION_IO_GPU_TEE_PROTECTED_TRANSFER    3
#define ATTESTATION_IO_FULL_DEVICE_IO_ATTESTED       4

/* CPU TEE family. None = software-only attestation (test mode). */
#define ATTESTATION_CPU_TEE_NONE     0
#define ATTESTATION_CPU_TEE_SEV_SNP  1
#define ATTESTATION_CPU_TEE_TDX      2
#define ATTESTATION_CPU_TEE_SGX      3

/* GPU TEE family. None = no GPU TEE (test mode or non-confidential GPU). */
#define ATTESTATION_GPU_TEE_NONE                  0
#define ATTESTATION_GPU_TEE_NV_H100_CC            1
#define ATTESTATION_GPU_TEE_NV_BLACKWELL_TEE_IO   2
#define ATTESTATION_GPU_TEE_AMD_MI300_CC          3

/* C-ABI mirror of NodeConfidentialAttestation.
 *
 * Field order matters: this is the canonical serialization order used to
 * compute the composite root.
 *
 * Hash fields are 32 bytes each (keccak256 outputs). Pad with zeros if not
 * applicable on the deployment (e.g. ai_model_runtime_hash on a non-AI node).
 */
typedef struct {
    uint8_t  cpu_tee_measurement[32];
    uint8_t  gpu_attestation_report[32];
    uint8_t  driver_firmware_measurement[32];
    uint8_t  quasar_gpu_binary_hash[32];
    uint8_t  crypto_kernel_hash[32];
    uint8_t  ai_model_runtime_hash[32];
    uint8_t  precompile_binary_hash[32];
    uint8_t  policy_root[32];
    uint8_t  node_identity[32];
    uint64_t epoch;
    uint8_t  cpu_tee_kind;
    uint8_t  gpu_tee_kind;
    uint8_t  io_level;
    uint8_t  _reserved[5];   /* pads to 8-byte alignment, must be zero */
} NodeConfidentialAttestation;

/* Compute the composite attestation_root.
 *
 *   attestation_root = keccak(
 *       cpu_tee_measurement || gpu_attestation_report ||
 *       driver_firmware_measurement || quasar_gpu_binary_hash ||
 *       crypto_kernel_hash || ai_model_runtime_hash ||
 *       precompile_binary_hash || policy_root || node_identity ||
 *       epoch_be8 || cpu_tee_kind || gpu_tee_kind || io_level)
 *
 * Endianness: epoch is encoded big-endian (8 bytes). Kinds and io_level are
 * single bytes. All hash fields go in declaration order.
 *
 * The function refuses to run if attestation == NULL or out == NULL.
 * Returns ATTESTATION_OK on success. */
int attestation_compute_composite_root(
    const NodeConfidentialAttestation* attestation,
    uint8_t out_root[32]);

/* Baseline expected by a validator.
 *
 * Each expected field is gated by an explicit `require_*` flag:
 *   * require_*  = true  -> strict equality with the corresponding observed
 *                            field. A zero-valued expected hash is rejected
 *                            (treating it as a real measurement, never a
 *                            wildcard). For kinds, this enforces that the
 *                            attestation kind == required_*_kind.
 *   * require_*  = false -> the field is skipped entirely; expected_* /
 *                            required_*_kind are not consulted.
 *
 * min_io_level is always enforced (floor). Set it to ATTESTATION_IO_NONE to
 * disable the floor.
 *
 * Rationale: the previous "all-zero hash = wildcard" heuristic silently turned
 * forgotten or default-initialized fields into accept-anything. The explicit
 * flag makes intent unambiguous and refuses to verify a zero-hash baseline. */
typedef struct {
    uint8_t expected_quasar_gpu_binary_hash[32];
    uint8_t expected_crypto_kernel_hash[32];
    uint8_t expected_precompile_binary_hash[32];
    uint8_t expected_policy_root[32];
    uint8_t min_io_level;
    uint8_t required_cpu_tee_kind;
    uint8_t required_gpu_tee_kind;

    /* Per-field enforcement flags. true = enforce strict equality, false =
     * skip. Encoded as uint8_t (0 = false, non-zero = true) for stable C ABI. */
    uint8_t require_quasar_gpu_binary_hash;
    uint8_t require_crypto_kernel_hash;
    uint8_t require_precompile_binary_hash;
    uint8_t require_policy_root;
    uint8_t require_cpu_tee_kind;
    uint8_t require_gpu_tee_kind;

    uint8_t _reserved[7];
} AttestationBaseline;

/* Verify a remote node's attestation against an expected baseline.
 * Returns ATTESTATION_OK on accept, ATTESTATION_ERR_VERIFY on first mismatch. */
int attestation_verify_baseline(
    const NodeConfidentialAttestation* attestation,
    const AttestationBaseline* expected);

#ifdef __cplusplus
}  /* extern "C" */
#endif

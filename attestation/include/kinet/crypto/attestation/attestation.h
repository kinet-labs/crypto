/*
 * Confidential-compute attestation primitives for kinet-labs/crypto.
 *
 *   * AMD SEV-SNP attestation report parser  -- 32-byte measurement extract
 *   * Intel TDX TD Quote parser              -- 32-byte MRTD extract
 *   * NVIDIA NRAS evidence parser            -- 32-byte canonical hash
 *
 * Real hardware provisioning is platform-deployment work; this header ships
 * the software primitives that can be tested against canned evidence and
 * later wired to live providers (PSP, QGS, NRAS).
 *
 * All parsers handle malformed evidence gracefully: they return a negative
 * error code and never read past the supplied buffer.
 *
 * Symbols are brand-neutral. The brand lives in the include path.
 */
#ifndef KINET_CRYPTO_ATTESTATION_H
#define KINET_CRYPTO_ATTESTATION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes (matches kinet_crypto.h). */
#define ATTESTATION_OK          0
#define ATTESTATION_ERR_INPUT  -1
#define ATTESTATION_ERR_LENGTH -2
#define ATTESTATION_ERR_VERIFY -3
#define ATTESTATION_ERR_NOTIMPL -5

/* AMD SEV-SNP attestation report is 1184 bytes (PSP-signed). The MEASUREMENT
 * field at offset 0x90 is 48 bytes (SHA-384). We hash it to 32 bytes via
 * keccak256 so it can flow into the composite attestation_root. */
#define SEV_SNP_REPORT_SIZE   1184
#define SEV_SNP_MEASUREMENT_OFFSET 0x90
#define SEV_SNP_MEASUREMENT_SIZE   48

int attestation_parse_sev_snp(
    const uint8_t* report, size_t report_len,
    uint8_t out_measurement[32]);

/* Intel TDX TD Quote header (48 bytes) + TD Report Body (584 bytes). MRTD is
 * inside the TD Report Body at offset 0x10 (48 bytes). */
#define TDX_QUOTE_MIN_SIZE         632
#define TDX_REPORT_BODY_OFFSET     48
#define TDX_MRTD_OFFSET_IN_BODY    16
#define TDX_MRTD_SIZE              48

int attestation_parse_tdx(
    const uint8_t* quote, size_t quote_len,
    uint8_t out_mrtd[32]);

/* NVIDIA NRAS evidence is a structured CBOR-ish blob; we serialize the typed
 * fields canonically and hash the result. Minimum supported layout (v1):
 *
 *   bytes 0..31     gpu_uuid     (raw 16 bytes + 16 zero pad)
 *   bytes 32..63    vbios_hash   (32 bytes)
 *   bytes 64..95    driver_hash  (32 bytes)
 *   bytes 96..127   rim_hash     (32 bytes)
 *   bytes 128..N    psc_chain    (variable; included in the canonical hash)
 *
 * Total: 128 bytes minimum. */
#define NV_EVIDENCE_MIN_SIZE 128

int attestation_parse_nv(
    const uint8_t* evidence, size_t evidence_len,
    uint8_t out_report_hash[32]);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* KINET_CRYPTO_ATTESTATION_H */

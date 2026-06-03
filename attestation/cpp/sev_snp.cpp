// AMD SEV-SNP attestation report parser.
//
// The PSP-signed report is a fixed 1184-byte structure described in AMD
// publication 56860 "SEV Secure Nested Paging Firmware ABI Specification"
// §7.3 (ATTESTATION_REPORT). The fields we care about for v0.1:
//
//   offset 0x00  version            (uint32, must be 2 for SNP)
//   offset 0x04  guest_svn          (uint32)
//   offset 0x90  measurement        (48 bytes, SHA-384 of the launch digest)
//   offset 0x140 host_data          (32 bytes)
//   offset 0x2A0 signature          (ECDSA-P384 r||s, 144 bytes total)
//
// We extract the 48-byte measurement and hash it to 32 bytes via keccak256.
// Signature verification is intentionally separate (P-384 lives elsewhere);
// callers that need the signature checked do that as a precondition.

#include "kinet/crypto/attestation/attestation.h"
#include "kinet/crypto/keccak.h"

#include <cstring>

extern "C" int attestation_parse_sev_snp(
    const uint8_t* report, size_t report_len,
    uint8_t out_measurement[32]) {
    if (report == nullptr || out_measurement == nullptr) {
        return ATTESTATION_ERR_INPUT;
    }
    if (report_len != SEV_SNP_REPORT_SIZE) {
        return ATTESTATION_ERR_LENGTH;
    }

    // Sanity-check the version field. SNP reports use version 2 or 3.
    const uint32_t version =
        static_cast<uint32_t>(report[0])              |
        (static_cast<uint32_t>(report[1]) <<  8)      |
        (static_cast<uint32_t>(report[2]) << 16)      |
        (static_cast<uint32_t>(report[3]) << 24);
    if (version != 2 && version != 3) {
        return ATTESTATION_ERR_VERIFY;
    }

    // Extract the 48-byte measurement, hash to 32 bytes for the composite.
    keccak256(report + SEV_SNP_MEASUREMENT_OFFSET,
              SEV_SNP_MEASUREMENT_SIZE,
              out_measurement);
    return ATTESTATION_OK;
}

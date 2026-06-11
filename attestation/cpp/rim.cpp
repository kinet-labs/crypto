// Reference Integrity Manifest (RIM) verification.
//
// A RIM is the published list of expected hashes for the components of a
// platform: vbios, driver, GPU firmware, etc. The verifier compares the
// hashes reported in the attestation evidence against the trusted RIM
// fingerprints. v0.1 keeps this as a constant-time hash compare.
//
// SAFETY CONTRACT: parser-only.
//
// This translation unit decodes TEE evidence layout and computes
// measurement hashes. It does NOT verify cryptographic signatures or
// trust chains. Calling this function on untrusted bytes without prior
// chain verification is a security bug.
//
// Signature verification is performed by:
//   - SEV-SNP: kinetd/cc/attest/sev.go via go-sev-guest + AMD KDS
//   - TDX:     kinetd/cc/attest/tdx.go via go-tdx-guest + Intel PCS
//   - NRAS:    kinetd/cc/attest/nras.go via NRAS JWT + JWKS cache
//
// See LP-137-ACTUAL-STATE.md §Attestation for the architectural seam.

#include "kinet/crypto/attestation/attestation.h"

#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" int attestation_rim_compare(
    const uint8_t observed[32],
    const uint8_t expected[32]) {
    if (observed == nullptr || expected == nullptr) {
        return ATTESTATION_ERR_INPUT;
    }
    // Constant-time compare so RIM mismatches don't leak partial info.
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; ++i) {
        diff |= static_cast<uint8_t>(observed[i] ^ expected[i]);
    }
    return diff == 0 ? ATTESTATION_OK : ATTESTATION_ERR_VERIFY;
}

// NVIDIA NRAS attestation evidence parser.
//
// NVIDIA Remote Attestation Service (NRAS) returns a structured blob
// containing the GPU's confidential-compute evidence: GPU UUID, vbios hash,
// driver hash, RIM hash, and a PSC certificate chain.
//
// For v0.1 we accept a flat layout (CBOR / JWT decoding stays out of the
// crypto core; that lives in the consumer that talks to NRAS). The flat
// layout (v1, what consumers serialize) is:
//
//   bytes 0..31     gpu_uuid     (raw 16 bytes + 16 zero pad, or 32 bytes
//                                 of node-specific identifier)
//   bytes 32..63    vbios_hash   (32 bytes)
//   bytes 64..95    driver_hash  (32 bytes)
//   bytes 96..127   rim_hash     (32 bytes)
//   bytes 128..N    psc_chain    (variable; included in the canonical hash)
//
// The output is a 32-byte canonical hash (keccak of the concatenation of
// every byte we received). Concrete RIM verification happens in rim.cpp.

#include "kinet/crypto/attestation/attestation.h"
#include "kinet/crypto/keccak.h"

#include <cstring>

extern "C" int attestation_parse_nv(
    const uint8_t* evidence, size_t evidence_len,
    uint8_t out_report_hash[32]) {
    if (evidence == nullptr || out_report_hash == nullptr) {
        return ATTESTATION_ERR_INPUT;
    }
    if (evidence_len < NV_EVIDENCE_MIN_SIZE) {
        return ATTESTATION_ERR_LENGTH;
    }

    // Canonical hash over the entire evidence blob.
    keccak256(evidence, evidence_len, out_report_hash);
    return ATTESTATION_OK;
}

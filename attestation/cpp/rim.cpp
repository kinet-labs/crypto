// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Reference Integrity Manifest (RIM) verification.
//
// A RIM is the published list of expected hashes for the components of a
// platform: vbios, driver, GPU firmware, etc. The verifier compares the
// hashes reported in the attestation evidence against the trusted RIM
// fingerprints. v0.1 keeps this as a constant-time hash compare; richer
// signed-RIM verification (X.509 chain + ECDSA over the RIM bytes) lands
// when we have a trust anchor on file.

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

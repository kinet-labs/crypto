// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Intel TDX TD Quote parser.
//
// The TD Quote layout per Intel TDX DCAP "Quote Generation Service"
// specification:
//
//   bytes  0..47    Quote Header        (version, vendor, signing key info)
//   bytes 48..631   TD Report Body      (584 bytes; matches TDREPORT_STRUCT)
//   bytes 632..N    Signature data      (ECDSA-P256 + cert chain, variable)
//
// Inside the TD Report Body:
//   offset  0..15   TEE_TCB_SVN
//   offset 16..63   MRTD               (48 bytes -- the TD measurement)
//   offset 64..111  MRCONFIGID
//   offset 112..159 MROWNER
//
// We extract the 48-byte MRTD and hash it to 32 bytes.

#include "kinet/crypto/attestation/attestation.h"
#include "kinet/crypto/keccak.h"

#include <cstring>

extern "C" int attestation_parse_tdx(
    const uint8_t* quote, size_t quote_len,
    uint8_t out_mrtd[32]) {
    if (quote == nullptr || out_mrtd == nullptr) {
        return ATTESTATION_ERR_INPUT;
    }
    if (quote_len < TDX_QUOTE_MIN_SIZE) {
        return ATTESTATION_ERR_LENGTH;
    }

    // Header version: bytes 0..1 little-endian. Currently 4 (DCAP).
    const uint16_t version =
        static_cast<uint16_t>(quote[0]) |
        (static_cast<uint16_t>(quote[1]) << 8);
    if (version != 4 && version != 5) {
        return ATTESTATION_ERR_VERIFY;
    }

    const size_t mrtd_offset = TDX_REPORT_BODY_OFFSET + TDX_MRTD_OFFSET_IN_BODY;
    keccak256(quote + mrtd_offset, TDX_MRTD_SIZE, out_mrtd);
    return ATTESTATION_OK;
}

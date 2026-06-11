// SPDX-License-Identifier: Apache-2.0
//
// ipa_kat_test.cpp -- IPA prover/verifier KAT byte-equal vs Go reference.
//
//   1. 5 valid KATs at N=256: build commitment from poly, compare to Go;
//      generate proof, compare 544-byte serialization to Go canonical;
//      verify proof, expect ok.
//   2. 3 negative KATs: wrong-commitment / wrong-y / tampered-proof. All
//      must be rejected by check_proof.

#include "../cpp/ipa.hpp"
#include "ipa_kat.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

using kinet::crypto::ipa::Config;
using kinet::crypto::ipa::Element;
using kinet::crypto::ipa::Fr;
using kinet::crypto::ipa::IPAProof;
using kinet::crypto::ipa::Transcript;
using kinet::crypto::ipa::kVectorLength;
using kinet::crypto::ipa::kat::kIPAValidKatCount;
using kinet::crypto::ipa::kat::kIPAValidKats;
using kinet::crypto::ipa::kat::kIPANegKatCount;
using kinet::crypto::ipa::kat::kIPANegKats;

namespace {

bool eq32(const std::uint8_t a[32], const std::uint8_t b[32]) {
    return std::memcmp(a, b, 32) == 0;
}
bool eqN(const std::uint8_t* a, const std::uint8_t* b, std::size_t n) {
    return std::memcmp(a, b, n) == 0;
}

void hexN(const std::uint8_t* b, std::size_t n, char* out) {
    static const char* d = "0123456789abcdef";
    for (std::size_t i = 0; i < n; ++i) {
        out[2 * i] = d[(b[i] >> 4) & 0xF];
        out[2 * i + 1] = d[b[i] & 0xF];
    }
    out[2 * n] = 0;
}

}  // namespace

int main() {
    // Build the shared config (SRS + barycentric weights).
    Config cfg;
    if (!cfg.init()) {
        std::printf("[FAIL] cfg.init()\n");
        return 1;
    }

    int valid_ok = 0, valid_fail = 0;
    int neg_ok = 0, neg_fail = 0;

    // ---- 1. Valid KATs --------------------------------------------------
    for (int i = 0; i < kIPAValidKatCount; ++i) {
        const auto& k = kIPAValidKats[i];

        // Decode poly.
        Fr a[kVectorLength];
        bool ok = true;
        for (std::size_t j = 0; j < kVectorLength; ++j) {
            if (!Fr::from_bytes_le(k.poly_le + j * 32, a[j])) { ok = false; break; }
        }
        if (!ok) {
            std::printf("[FAIL] %s: poly[i] not canonical\n", k.name);
            ++valid_fail;
            continue;
        }
        Fr eval;
        if (!Fr::from_bytes_le(k.eval_le, eval)) {
            std::printf("[FAIL] %s: eval not canonical\n", k.name);
            ++valid_fail;
            continue;
        }

        // Commitment: must match Go.
        Element commitment = kinet::crypto::ipa::commit(cfg, a);
        std::uint8_t got_commit[32];
        commitment.serialize_compressed(got_commit);
        if (!eq32(got_commit, k.commit_be)) {
            char hg[65], hw[65];
            hexN(got_commit, 32, hg);
            hexN(k.commit_be, 32, hw);
            std::printf("[FAIL] %s: commit mismatch\n  got : %s\n  want: %s\n",
                        k.name, hg, hw);
            ++valid_fail;
            continue;
        }

        // Generate proof.
        Transcript pt("ipa");
        IPAProof proof;
        Fr y;
        int rc = kinet::crypto::ipa::create_proof(cfg, pt, commitment, a, eval, proof, y);
        if (rc != 0) {
            std::printf("[FAIL] %s: create_proof rc=%d\n", k.name, rc);
            ++valid_fail;
            continue;
        }

        // y matches.
        std::uint8_t got_y[32];
        y.to_bytes_le(got_y);
        if (!eq32(got_y, k.y_le)) {
            char hg[65], hw[65];
            hexN(got_y, 32, hg);
            hexN(k.y_le, 32, hw);
            std::printf("[FAIL] %s: y mismatch\n  got : %s\n  want: %s\n",
                        k.name, hg, hw);
            ++valid_fail;
            continue;
        }

        // Proof bytes match.
        std::uint8_t got_proof[IPAProof::kSerializedSize];
        proof.serialize(got_proof);
        if (!eqN(got_proof, k.proof, IPAProof::kSerializedSize)) {
            std::printf("[FAIL] %s: proof bytes mismatch\n", k.name);
            // Show first 32 bytes mismatch context.
            for (std::size_t off = 0; off < IPAProof::kSerializedSize; off += 32) {
                if (!eq32(got_proof + off, k.proof + off)) {
                    char hg[65], hw[65];
                    hexN(got_proof + off, 32, hg);
                    hexN(k.proof + off, 32, hw);
                    std::printf("    @+%-3zu got : %s\n", off, hg);
                    std::printf("    @+%-3zu want: %s\n", off, hw);
                    break;
                }
            }
            ++valid_fail;
            continue;
        }

        // Verifier roundtrip.
        Transcript vt("ipa");
        int vrc = kinet::crypto::ipa::check_proof(cfg, vt, commitment, proof, eval, y);
        if (vrc != 0) {
            std::printf("[FAIL] %s: check_proof rc=%d\n", k.name, vrc);
            ++valid_fail;
            continue;
        }

        ++valid_ok;
        std::printf("[ok  ] %s: commit/y/proof byte-equal + verify ok\n", k.name);
    }

    // ---- 2. Negative KATs -----------------------------------------------
    for (int i = 0; i < kIPANegKatCount; ++i) {
        const auto& k = kIPANegKats[i];

        Element commitment;
        if (!Element::deserialize_compressed(k.commit_be, commitment)) {
            // Bad commitment encoding -> automatic rejection at decode is fine.
            ++neg_ok;
            std::printf("[ok  ] %s rejected at decode\n", k.name);
            continue;
        }
        Fr eval, y;
        if (!Fr::from_bytes_le(k.eval_le, eval) || !Fr::from_bytes_le(k.y_le, y)) {
            ++neg_ok;
            std::printf("[ok  ] %s rejected at scalar decode\n", k.name);
            continue;
        }
        IPAProof proof;
        if (!IPAProof::deserialize(k.proof, proof)) {
            ++neg_ok;
            std::printf("[ok  ] %s rejected at proof decode\n", k.name);
            continue;
        }

        Transcript vt("ipa");
        int vrc = kinet::crypto::ipa::check_proof(cfg, vt, commitment, proof, eval, y);
        if (vrc != 0) {
            ++neg_ok;
            std::printf("[ok  ] %s rejected by check_proof (rc=%d)\n", k.name, vrc);
        } else {
            std::printf("[FAIL] %s: check_proof accepted invalid input\n", k.name);
            ++neg_fail;
        }
    }

    std::printf("\n=== ipa_kat_test:\n"
                "    valid    : %d/%d ok, %d failures\n"
                "    negative : %d/%d ok, %d failures\n",
                valid_ok, kIPAValidKatCount, valid_fail,
                neg_ok, kIPANegKatCount, neg_fail);

    int failures = valid_fail + neg_fail;
    if (failures != 0) {
        std::printf("=== FAILED with %d failures\n", failures);
        return 1;
    }
    std::printf("=== ipa_kat_test: ALL PASS\n");
    return 0;
}

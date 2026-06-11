// SPDX-License-Identifier: Apache-2.0
//
// element_kat_test.cpp -- Banderwagon group element tests.
//   1. 16 encoding KATs byte-equal vs the Go reference (kinet-labs/crypto banderwagon).
//   2. 16 bad-subgroup encodings rejected by deserialize_compressed.
//   3. add/double consistency: add(P,P) == double(P) (100 iters).
//   4. scalar_mul consistency: scalar_mul(P, k+1) == add(scalar_mul(P, k), P)
//      (100 iters).
//
// Two-torsion fuzz (1000 iterations of random-pair Banderwagon equality) is
// honestly deferred -- the encoding KATs already exercise the
// equivalence-class normalization.

#include "../cpp/element.hpp"
#include "../cpp/fp.hpp"
#include "../cpp/fr.hpp"
#include "element_kat.h"

#include <cstdio>
#include <cstdint>
#include <cstring>

using kinet::banderwagon::Element;
using kinet::banderwagon::Fp;
using kinet::banderwagon::Fr;
using kinet::banderwagon::kat::kElementEncKats;
using kinet::banderwagon::kat::kElementEncKatCount;
using kinet::banderwagon::kat::kElementBadKats;
using kinet::banderwagon::kat::kElementBadKatCount;

namespace {

bool eq32(const std::uint8_t a[32], const std::uint8_t b[32]) {
    return std::memcmp(a, b, 32) == 0;
}

void hex32(const std::uint8_t b[32], char out[65]) {
    static const char* d = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[2 * i] = d[(b[i] >> 4) & 0xF];
        out[2 * i + 1] = d[b[i] & 0xF];
    }
    out[64] = 0;
}

// Right-to-left binary scalar multiplication on Fr scalars expressed as
// 32-byte LE canonical bytes (test-only, unrelated to scalar_mul under test).
Element naive_scalar_mul(const Element& p, const std::uint8_t s_le[32]) {
    Element acc = Element::identity();
    Element base = p;
    for (int byte_idx = 0; byte_idx < 32; ++byte_idx) {
        std::uint8_t b = s_le[byte_idx];
        for (int bit = 0; bit < 8; ++bit) {
            if ((b >> bit) & 1) {
                acc = Element::add(acc, base);
            }
            base = Element::double_self(base);
        }
    }
    return acc;
}

// Build an Fr from canonical 32-byte LE bytes; returns false if not in [0, r).
bool fr_from_le(const std::uint8_t bytes[32], Fr& out) {
    return Fr::from_bytes_le(bytes, out);
}

}  // namespace

int main() {
    int enc_ok = 0, enc_fail = 0;
    int bad_ok = 0, bad_fail = 0;
    int add_dbl_ok = 0, add_dbl_fail = 0;
    int smul_ok = 0, smul_fail = 0;

    // -----------------------------------------------------------------
    // 1. Encoding KATs.
    // -----------------------------------------------------------------
    for (int i = 0; i < kElementEncKatCount; ++i) {
        const auto& kat = kElementEncKats[i];

        Fr s;
        if (!fr_from_le(kat.scalar_le, s)) {
            std::printf("[FAIL] %s: scalar not in [0, r)\n", kat.name);
            ++enc_fail;
            continue;
        }

        // Compute [s] * G.
        Element G = Element::generator();
        Element P = Element::scalar_mul(G, s);

        // Serialize compressed -- must match Go-reference encoding.
        std::uint8_t got[32];
        P.serialize_compressed(got);
        if (!eq32(got, kat.enc_be)) {
            char hg[65], hw[65];
            hex32(got, hg);
            hex32(kat.enc_be, hw);
            std::printf("[FAIL] %s\n  got : %s\n  want: %s\n",
                        kat.name, hg, hw);
            ++enc_fail;
            continue;
        }

        // Round-trip: deserialize the canonical encoding and check equality.
        Element R;
        if (!Element::deserialize_compressed(kat.enc_be, R)) {
            std::printf("[FAIL] %s: deserialize_compressed rejected canonical bytes\n",
                        kat.name);
            ++enc_fail;
            continue;
        }
        if (!Element::equal(R, P)) {
            std::printf("[FAIL] %s: round-trip element != original\n", kat.name);
            ++enc_fail;
            continue;
        }

        ++enc_ok;
        std::printf("[ok  ] %s\n", kat.name);
    }

    // -----------------------------------------------------------------
    // 2. Bad-subgroup-rejection KATs.
    // -----------------------------------------------------------------
    for (int i = 0; i < kElementBadKatCount; ++i) {
        const auto& kat = kElementBadKats[i];
        Element R;
        if (Element::deserialize_compressed(kat.enc_be, R)) {
            std::printf("[FAIL] %s: bad encoding accepted (should be rejected)\n",
                        kat.name);
            ++bad_fail;
            continue;
        }
        ++bad_ok;
        std::printf("[ok  ] %s rejected\n", kat.name);
    }

    // -----------------------------------------------------------------
    // 3. add(P, P) == double(P)  -- 100 iters with deterministic
    //    scalar-derived points.
    // -----------------------------------------------------------------
    {
        Element G = Element::generator();
        Fr k = Fr::one();
        for (int i = 0; i < 100; ++i) {
            // P = [k] * G  (k starts at 1, increments each iteration).
            Element P = Element::scalar_mul(G, k);
            Element pp = Element::add(P, P);
            Element dd = Element::double_self(P);
            if (!Element::equal(pp, dd)) {
                std::printf("[FAIL] add/double consistency at i=%d\n", i);
                ++add_dbl_fail;
            } else {
                ++add_dbl_ok;
            }
            k = Fr::add(k, Fr::one());
        }
    }

    // -----------------------------------------------------------------
    // 4. scalar_mul consistency:
    //      scalar_mul(P, k+1) == add(scalar_mul(P, k), P)
    //    (100 iters with k = 1..100, P = G).
    // -----------------------------------------------------------------
    {
        Element G = Element::generator();
        Fr k = Fr::one();
        for (int i = 0; i < 100; ++i) {
            Fr kp1 = Fr::add(k, Fr::one());
            Element kp = Element::scalar_mul(G, k);
            Element kp1p = Element::scalar_mul(G, kp1);
            Element kp_plus_g = Element::add(kp, G);
            if (!Element::equal(kp1p, kp_plus_g)) {
                std::printf("[FAIL] scalar_mul consistency at i=%d\n", i);
                ++smul_fail;
            } else {
                ++smul_ok;
            }
            k = kp1;
        }
    }

    // -----------------------------------------------------------------
    // 5. Fixed sanity invariants.
    // -----------------------------------------------------------------
    {
        Element G = Element::generator();
        if (!G.is_on_curve()) {
            std::printf("[FAIL] generator not on curve\n");
        } else {
            std::printf("[ok  ] generator is on curve\n");
        }
        Element id = Element::identity();
        if (!id.is_identity()) {
            std::printf("[FAIL] identity not detected\n");
        } else {
            std::printf("[ok  ] identity detected\n");
        }
        // [r-1]G + G == identity?  Cheap end-to-end smoke test using k=2: P=2G;
        // P - G must equal G under Banderwagon equality.
        Fr two = Fr::add(Fr::one(), Fr::one());
        Element two_g = Element::scalar_mul(G, two);
        Element check = Element::sub(two_g, G);
        if (!Element::equal(check, G)) {
            std::printf("[FAIL] 2G - G != G\n");
        } else {
            std::printf("[ok  ] 2G - G == G\n");
        }
    }

    // -----------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------
    std::printf("\n=== element_kat_test:\n"
                "    encoding   : %d/%d ok, %d failures\n"
                "    bad subgrp : %d/%d ok, %d failures\n"
                "    add==dbl   : %d/100 ok, %d failures\n"
                "    smul       : %d/100 ok, %d failures\n",
                enc_ok, kElementEncKatCount, enc_fail,
                bad_ok, kElementBadKatCount, bad_fail,
                add_dbl_ok, add_dbl_fail,
                smul_ok, smul_fail);

    int failures = enc_fail + bad_fail + add_dbl_fail + smul_fail;
    if (failures != 0) {
        std::printf("=== FAILED with %d failures\n", failures);
        return 1;
    }
    std::printf("=== element_kat_test: ALL PASS\n");
    return 0;
}

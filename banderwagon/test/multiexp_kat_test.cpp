// SPDX-License-Identifier: Apache-2.0
//
// multiexp_kat_test.cpp -- Banderwagon Pippenger MSM tests.
//
//   1. 1000 random MSM iterations across N in {1, 2, 8, 64, 256, 1024}
//      byte-equal vs the Go gnark reference (kinet-labs/crypto/ipa/banderwagon
//      Element.MultiExp).
//   2. Edge cases:
//        N=0  -> identity (encoded as 32 zero bytes)
//        N=1  -> consistent with Element::scalar_mul(P, s)
//        N=2  -> small-N path
//
// Inputs (points and scalars) are reproduced from the *same* xorshift64*
// PRG and seed mix used by gen_multiexp_kat.go, so only the expected
// 32-byte compressed encoding of the MSM result needs to ship in the
// header.

#include "../cpp/element.hpp"
#include "../cpp/fr.hpp"
#include "../cpp/multiexp.hpp"
#include "multiexp_kat.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using kinet::banderwagon::Element;
using kinet::banderwagon::Fr;
using kinet::banderwagon::multi_scalar_mul;
using kinet::banderwagon::kat::kMsmKatCount;
using kinet::banderwagon::kat::kMsmKats;
using kinet::banderwagon::kat::MsmKat;

namespace {

// xorshift64* matching gen_multiexp_kat.go bit-exactly.
struct DetRng {
    std::uint64_t s;
    explicit DetRng(std::uint64_t seed) : s(seed) {}
    std::uint64_t next() {
        std::uint64_t x = s;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s = x;
        return x * 2685821657736338717ULL;
    }
    void fill32(std::uint8_t buf[32]) {
        for (int i = 0; i < 4; ++i) {
            std::uint64_t v = next();
            buf[8 * i + 0] = static_cast<std::uint8_t>(v);
            buf[8 * i + 1] = static_cast<std::uint8_t>(v >> 8);
            buf[8 * i + 2] = static_cast<std::uint8_t>(v >> 16);
            buf[8 * i + 3] = static_cast<std::uint8_t>(v >> 24);
            buf[8 * i + 4] = static_cast<std::uint8_t>(v >> 32);
            buf[8 * i + 5] = static_cast<std::uint8_t>(v >> 40);
            buf[8 * i + 6] = static_cast<std::uint8_t>(v >> 48);
            buf[8 * i + 7] = static_cast<std::uint8_t>(v >> 56);
        }
    }
};

// Build an Fr from a small unsigned 64-bit integer (<= 2^64 - 1).
Fr fr_from_uint64(std::uint64_t k) {
    std::uint8_t buf[32] = {0};
    buf[0] = static_cast<std::uint8_t>(k);
    buf[1] = static_cast<std::uint8_t>(k >> 8);
    buf[2] = static_cast<std::uint8_t>(k >> 16);
    buf[3] = static_cast<std::uint8_t>(k >> 24);
    buf[4] = static_cast<std::uint8_t>(k >> 32);
    buf[5] = static_cast<std::uint8_t>(k >> 40);
    buf[6] = static_cast<std::uint8_t>(k >> 48);
    buf[7] = static_cast<std::uint8_t>(k >> 56);
    Fr out;
    Fr::from_bytes_le(buf, out);
    return out;
}

// Reproduce the Go genPoint stream: pull one uint64, take low 32 bits, +1,
// scalar_mul with Generator.
Element gen_point(DetRng& rng) {
    std::uint64_t v = rng.next();
    std::uint64_t k = (v & 0xFFFFFFFFu) + 1u;
    Fr s = fr_from_uint64(k);
    return Element::scalar_mul(Element::generator(), s);
}

// Reproduce the Go genScalar stream: 32 bytes from PRG, mask buf[31] &= 0x07,
// build Fr.
Fr gen_scalar(DetRng& rng) {
    std::uint8_t buf[32];
    rng.fill32(buf);
    buf[31] &= 0x07;
    Fr out;
    Fr::from_bytes_le(buf, out);
    return out;
}

bool eq32(const std::uint8_t a[32], const std::uint8_t b[32]) {
    return std::memcmp(a, b, 32) == 0;
}

void hex32(const std::uint8_t b[32], char out[65]) {
    static const char* d = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[2 * i]     = d[(b[i] >> 4) & 0xF];
        out[2 * i + 1] = d[b[i] & 0xF];
    }
    out[64] = 0;
}

}  // namespace

int main() {
    int kat_ok = 0, kat_fail = 0;
    int edge_ok = 0, edge_fail = 0;

    // -----------------------------------------------------------------
    // 1. KAT byte-equality (1000 iterations)
    // -----------------------------------------------------------------
    int verbose_failures_remaining = 5;  // print at most a few failure reports
    for (int i = 0; i < kMsmKatCount; ++i) {
        const MsmKat& k = kMsmKats[i];

        DetRng rng(k.seed);
        std::vector<Element> points(k.n);
        std::vector<Fr>      scalars(k.n);
        for (std::size_t j = 0; j < k.n; ++j) points[j]  = gen_point(rng);
        for (std::size_t j = 0; j < k.n; ++j) scalars[j] = gen_scalar(rng);

        Element result = multi_scalar_mul(points.data(), scalars.data(), k.n);

        std::uint8_t got[32];
        result.serialize_compressed(got);

        if (!eq32(got, k.enc_be)) {
            ++kat_fail;
            if (verbose_failures_remaining-- > 0) {
                char hg[65], hw[65];
                hex32(got, hg);
                hex32(k.enc_be, hw);
                std::printf("[FAIL] %s (n=%zu)\n  got : %s\n  want: %s\n",
                            k.name, k.n, hg, hw);
            }
            continue;
        }
        ++kat_ok;
    }

    // -----------------------------------------------------------------
    // 2. Edge cases.
    //    a. N=0 returns identity (encoded as 32 zero bytes per Banderwagon
    //       compressed serialization for the (X=0, Y=Z) point).
    //    b. N=1 must equal scalar_mul(P, s).
    //    c. N=2 path correctness vs naive sum.
    // -----------------------------------------------------------------
    {
        // 2a. N == 0 -> identity
        Element id = multi_scalar_mul(nullptr, nullptr, 0);
        if (!id.is_identity()) {
            std::printf("[FAIL] N=0 did not return identity\n");
            ++edge_fail;
        } else {
            std::uint8_t enc[32];
            id.serialize_compressed(enc);
            std::uint8_t zeros[32] = {0};
            if (!eq32(enc, zeros)) {
                std::printf("[FAIL] N=0 identity encoded != 32 zero bytes\n");
                ++edge_fail;
            } else {
                ++edge_ok;
                std::printf("[ok  ] N=0 -> identity (32 zero bytes)\n");
            }
        }
    }
    {
        // 2b. N == 1 vs scalar_mul.
        // Pick a deterministic point/scalar pair from a fresh PRG.
        DetRng rng(0xdeadbeefcafebabeULL);
        Element P = gen_point(rng);
        Fr s      = gen_scalar(rng);

        Element via_msm    = multi_scalar_mul(&P, &s, 1);
        Element via_smul   = Element::scalar_mul(P, s);
        if (!Element::equal(via_msm, via_smul)) {
            std::printf("[FAIL] N=1 MSM != scalar_mul\n");
            ++edge_fail;
        } else {
            ++edge_ok;
            std::printf("[ok  ] N=1 == scalar_mul(P, s)\n");
        }
    }
    {
        // 2c. N == 2 vs (s0*P0 + s1*P1).
        DetRng rng(0xfeedfacefeedfaceULL);
        Element pts[2]  = { gen_point(rng), gen_point(rng) };
        Fr      sc[2]   = { gen_scalar(rng), gen_scalar(rng) };

        Element via_msm  = multi_scalar_mul(pts, sc, 2);
        Element naive    = Element::add(
            Element::scalar_mul(pts[0], sc[0]),
            Element::scalar_mul(pts[1], sc[1]));
        if (!Element::equal(via_msm, naive)) {
            std::printf("[FAIL] N=2 MSM != s0*P0 + s1*P1\n");
            ++edge_fail;
        } else {
            ++edge_ok;
            std::printf("[ok  ] N=2 == s0*P0 + s1*P1\n");
        }
    }

    // -----------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------
    std::printf("\n=== multiexp_kat_test:\n"
                "    KAT       : %d/%d ok, %d failures\n"
                "    edges     : %d/3 ok, %d failures\n",
                kat_ok, kMsmKatCount, kat_fail,
                edge_ok, edge_fail);

    int failures = kat_fail + edge_fail;
    if (failures != 0) {
        std::printf("=== FAILED with %d failures\n", failures);
        return 1;
    }
    std::printf("=== multiexp_kat_test: ALL PASS\n");
    return 0;
}

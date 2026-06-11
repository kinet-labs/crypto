// SPDX-License-Identifier: Apache-2.0
//
// fp_kat_test.cpp -- KAT correctness vs gnark-crypto bls12-381/fr (Bandersnatch
// base field). 10 vectors total: 5 add, 5 mul. Byte-equality required.

#include "../cpp/fp.hpp"
#include "fp_kat.h"

#include <cstdio>
#include <cstring>

using kinet::banderwagon::Fp;
using kinet::banderwagon::kat::kFpKats;
using kinet::banderwagon::kat::kFpKatCount;

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

}  // namespace

int main() {
    int ok = 0;
    int fail = 0;

    for (int i = 0; i < kFpKatCount; ++i) {
        const auto& v = kFpKats[i];

        Fp a, b;
        if (!Fp::from_bytes_le(v.a, a)) {
            std::printf("[FAIL] %s: from_bytes_le(a) rejected canonical input\n", v.name);
            ++fail;
            continue;
        }
        if (!Fp::from_bytes_le(v.b, b)) {
            std::printf("[FAIL] %s: from_bytes_le(b) rejected canonical input\n", v.name);
            ++fail;
            continue;
        }

        Fp r;
        if (std::strcmp(v.op, "add") == 0) {
            r = Fp::add(a, b);
        } else if (std::strcmp(v.op, "mul") == 0) {
            r = Fp::mul(a, b);
        } else {
            std::printf("[FAIL] %s: unknown op %s\n", v.name, v.op);
            ++fail;
            continue;
        }

        std::uint8_t got[32];
        r.to_bytes_le(got);

        if (!eq32(got, v.r)) {
            char hg[65], hw[65];
            hex32(got, hg);
            hex32(v.r, hw);
            std::printf("[FAIL] %s (%s)\n  got : %s\n  want: %s\n",
                        v.name, v.op, hg, hw);
            ++fail;
            continue;
        }

        ++ok;
        std::printf("[ok  ] %s (%s)\n", v.name, v.op);
    }

    // Round-trip + algebraic invariants.
    {
        Fp z = Fp::zero();
        Fp o = Fp::one();
        std::uint8_t bz[32], bo[32];
        z.to_bytes_le(bz);
        o.to_bytes_le(bo);
        std::uint8_t want_zero[32] = {0};
        std::uint8_t want_one[32] = {0};
        want_one[0] = 1;
        if (!eq32(bz, want_zero)) {
            std::printf("[FAIL] zero().to_bytes_le()\n");
            ++fail;
        } else {
            std::printf("[ok  ] zero round-trip\n");
        }
        if (!eq32(bo, want_one)) {
            std::printf("[FAIL] one().to_bytes_le()\n");
            ++fail;
        } else {
            std::printf("[ok  ] one round-trip\n");
        }

        // a * a^{-1} == 1 (using the second mul KAT input which is non-zero).
        Fp a;
        if (Fp::from_bytes_le(kFpKats[6].a, a) && !a.is_zero()) {
            Fp ainv = Fp::inv(a);
            Fp prod = Fp::mul(a, ainv);
            if (!prod.is_one()) {
                std::printf("[FAIL] a * a^{-1} != 1\n");
                ++fail;
            } else {
                std::printf("[ok  ] inv * a == 1\n");
            }
        }

        // -(-a) == a
        Fp a2;
        Fp::from_bytes_le(kFpKats[3].a, a2);
        Fp neg = Fp::neg(a2);
        Fp neg2 = Fp::neg(neg);
        if (!a2.equal(neg2)) {
            std::printf("[FAIL] -(-a) != a\n");
            ++fail;
        } else {
            std::printf("[ok  ] -(-a) == a\n");
        }

        // square(a) == mul(a,a)
        Fp sq = Fp::square(a2);
        Fp mu = Fp::mul(a2, a2);
        if (!sq.equal(mu)) {
            std::printf("[FAIL] square(a) != mul(a,a)\n");
            ++fail;
        } else {
            std::printf("[ok  ] square == mul(a,a)\n");
        }
    }

    std::printf("\n=== fp_kat_test: KAT %d/%d PASS, %d failures ===\n",
                ok, kFpKatCount, fail);
    return fail == 0 ? 0 : 1;
}

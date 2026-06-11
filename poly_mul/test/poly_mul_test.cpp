// Copyright (C) 2020-2026, Kinet Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Byte-equal KAT test: every (n, seedA, seedB, sum, first, last) tuple
// must match poly_mul_test.go exactly. If a number changes, both files
// change in lockstep.

#include "poly_mul.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

using kinet::crypto::poly_mul::Q;
using kinet::crypto::poly_mul::MaxLogN;
using kinet::crypto::poly_mul::mul;
using kinet::crypto::poly_mul::mul_schoolbook;
using kinet::crypto::poly_mul::mul_ntt;
using kinet::crypto::poly_mul::ntt_forward;
using kinet::crypto::poly_mul::ntt_inverse;

static int failures = 0;
static int tests = 0;

#define EXPECT(cond, ...) do { \
    ++tests; \
    if (!(cond)) { \
        ++failures; \
        std::fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
        std::fprintf(stderr, __VA_ARGS__); \
        std::fprintf(stderr, "\n"); \
    } \
} while (0)

// Same LCG used by Go test
static std::vector<uint64_t> lcg(uint64_t seed, size_t n) {
    std::vector<uint64_t> out(n);
    uint64_t state = seed;
    for (size_t i = 0; i < n; ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = state % Q;
    }
    return out;
}

static void check_kat(const char* label,
                      const std::vector<uint64_t>& c,
                      uint64_t want_sum,
                      uint64_t want_first,
                      uint64_t want_last) {
    uint64_t sum = 0;
    for (auto v : c) {
        EXPECT(v < Q, "%s: out-of-range %llu", label, (unsigned long long)v);
        sum = (sum + v) % Q;
    }
    EXPECT(sum == want_sum, "%s: sum got %llu want %llu", label,
           (unsigned long long)sum, (unsigned long long)want_sum);
    EXPECT(c.front() == want_first, "%s: first got %llu want %llu", label,
           (unsigned long long)c.front(), (unsigned long long)want_first);
    EXPECT(c.back() == want_last, "%s: last got %llu want %llu", label,
           (unsigned long long)c.back(), (unsigned long long)want_last);
}

struct KAT {
    const char* name;
    size_t n;
    uint64_t sA;
    uint64_t sB;
    uint64_t sum;
    uint64_t first;
    uint64_t last;
};

int main() {
    static const KAT kats[] = {
        {"n2", 2, 0x1, 0x2, 567996115, 371012399, 196983716},
        {"n4", 4, 0x64, 0xc8, 935898137, 410827071, 376044324},
        {"n8", 8, 0x4d2, 0x162e, 48246169, 673146415, 767542882},
        {"n16", 16, 0xdeadbeef, 0xcafebabe, 590901354, 41636199, 860993788},
        {"n32", 32, 0x7, 0xd, 72828809, 392054258, 84461645},
        {"n64", 64, 0xb, 0x11, 933631914, 967956798, 522099145},
        {"n128", 128, 0x13, 0x17, 443591268, 429303763, 461383520},
        {"n256", 256, 0x1, 0x2, 78388485, 359306289, 229818328},
        {"n512", 512, 0x1f, 0x25, 723079964, 641254315, 816782592},
        {"n1024", 1024, 0x29, 0x2b, 308246040, 8552215, 931224377},
    };

    for (const auto& tc : kats) {
        auto a = lcg(tc.sA, tc.n);
        auto b = lcg(tc.sB, tc.n);

        auto cs = mul_schoolbook(a, b);
        check_kat(tc.name, cs, tc.sum, tc.first, tc.last);

        if (tc.n >= 2 && (tc.n & (tc.n - 1)) == 0 && tc.n <= (size_t(1) << MaxLogN) / 2) {
            auto cn = mul_ntt(a, b);
            check_kat(tc.name, cn, tc.sum, tc.first, tc.last);
            EXPECT(cs.size() == cn.size(), "%s: size mismatch", tc.name);
            for (size_t i = 0; i < cs.size(); ++i) {
                EXPECT(cs[i] == cn[i], "%s: schoolbook[%zu]=%llu != ntt=%llu",
                       tc.name, i, (unsigned long long)cs[i], (unsigned long long)cn[i]);
            }
        }

        auto cd = mul(a, b);
        check_kat(tc.name, cd, tc.sum, tc.first, tc.last);
    }

    // Handwritten cases
    {
        std::vector<uint64_t> a = {1, 2, 3, 4};
        std::vector<uint64_t> b = {5, 6, 7, 8};
        std::vector<uint64_t> want = {998244297, 998244317, 2, 60};
        auto got = mul_schoolbook(a, b);
        EXPECT(got == want, "handwritten 1234*5678 mismatch");
        auto got2 = mul_ntt(a, b);
        EXPECT(got2 == want, "ntt handwritten 1234*5678 mismatch");
    }
    {
        std::vector<uint64_t> a = {0, 1, 0, 0};
        std::vector<uint64_t> b = {1, 1, 1, 1};
        std::vector<uint64_t> want = {Q - 1, 1, 1, 1};
        auto got = mul_schoolbook(a, b);
        EXPECT(got == want, "X*Sigma mismatch");
    }
    {
        std::vector<uint64_t> a = {1, 0, 0, 0};
        std::vector<uint64_t> b = {1, 0, 0, 0};
        std::vector<uint64_t> want = {1, 0, 0, 0};
        auto got = mul_schoolbook(a, b);
        EXPECT(got == want, "1*1 mismatch");
    }

    // NTT roundtrip for log_n in [1..10]
    for (int log_n = 1; log_n <= 10; ++log_n) {
        size_t n = size_t(1) << log_n;
        auto data = lcg(uint64_t(log_n) * 0x1234567ULL, n);
        auto orig = data;
        bool ok = ntt_forward(data);
        EXPECT(ok, "log_n=%d ntt_forward failed", log_n);
        ok = ntt_inverse(data);
        EXPECT(ok, "log_n=%d ntt_inverse failed", log_n);
        for (size_t i = 0; i < n; ++i) {
            EXPECT(data[i] == orig[i], "log_n=%d roundtrip differs at %zu: got %llu want %llu",
                   log_n, i, (unsigned long long)data[i], (unsigned long long)orig[i]);
        }
    }

    std::printf("poly_mul: %d/%d passed\n", tests - failures, tests);
    return failures == 0 ? 0 : 1;
}

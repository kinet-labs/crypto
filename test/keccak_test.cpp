// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Test vectors for kinet_keccak256 (Ethereum-style Keccak-256 with delimiter 0x01).
// Vectors taken from the original Keccak team's reference (publicly published).

#include "kinet/crypto/keccak.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>

static int g_failures = 0;

static std::string hex(const uint8_t* b, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string r; r.reserve(n*2);
    for (size_t i = 0; i < n; ++i) { r.push_back(H[b[i] >> 4]); r.push_back(H[b[i] & 0xF]); }
    return r;
}

static void check(const char* name, const uint8_t* in, size_t n, const char* expect_hex) {
    uint8_t got[32];
    kinet_keccak256(in, n, got);
    std::string g = hex(got, 32);
    if (g == expect_hex) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s\n  got  %s\n  want %s\n", name, g.c_str(), expect_hex);
        ++g_failures;
    }
}

int main() {
    std::fprintf(stdout, "=== kinet_keccak256 test suite ===\n");

    // Empty string
    check("keccak256(\"\")", nullptr, 0,
          "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

    // "abc"
    {
        const uint8_t in[] = {'a','b','c'};
        check("keccak256(\"abc\")", in, 3,
              "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    }

    // 56-byte string (one block boundary case for SHA-3 family)
    {
        const char* s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        check("keccak256(56-byte)", (const uint8_t*)s, 56,
              "45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371");
    }

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
        g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
        g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}

// Test vectors for RIPEMD-160 from Dobbertin et al., 1996 reference paper.

#include "crypto.h"
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
    uint8_t got[20];
    int rc = ripemd160(in, n, got);
    if (rc != CRYPTO_OK) {
        std::fprintf(stderr, "FAIL %s (rc=%d)\n", name, rc);
        ++g_failures;
        return;
    }
    std::string g = hex(got, 20);
    if (g == expect_hex) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s\n  got  %s\n  want %s\n", name, g.c_str(), expect_hex);
        ++g_failures;
    }
}

int main() {
    std::fprintf(stdout, "=== ripemd160 test suite ===\n");

    // Reference vectors from "RIPEMD-160: A Strengthened Version of RIPEMD"
    // (Dobbertin, Bosselaers, Preneel, 1996).
    check("ripemd160(\"\")", nullptr, 0,
          "9c1185a5c5e9fc54612808977ee8f548b2258d31");

    {
        const uint8_t in[] = {'a'};
        check("ripemd160(\"a\")", in, 1,
              "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
    }

    {
        const uint8_t in[] = {'a','b','c'};
        check("ripemd160(\"abc\")", in, 3,
              "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    }

    {
        const char* s = "message digest";
        check("ripemd160(\"message digest\")", (const uint8_t*)s, 14,
              "5d0689ef49d2fae572b881b123a85ffa21595f36");
    }

    {
        const char* s = "abcdefghijklmnopqrstuvwxyz";
        check("ripemd160(a-z)", (const uint8_t*)s, 26,
              "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
    }

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
        g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
        g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}

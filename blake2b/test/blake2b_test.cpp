// Test vectors for BLAKE2b-512 (RFC 7693 Appendix B).

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
    uint8_t got[64];
    int rc = blake2b(in, n, got);
    if (rc != CRYPTO_OK) {
        std::fprintf(stderr, "FAIL %s (rc=%d)\n", name, rc);
        ++g_failures;
        return;
    }
    std::string g = hex(got, 64);
    if (g == expect_hex) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s\n  got  %s\n  want %s\n", name, g.c_str(), expect_hex);
        ++g_failures;
    }
}

int main() {
    std::fprintf(stdout, "=== blake2b test suite ===\n");

    // RFC 7693 Appendix A: BLAKE2b-512 of empty input.
    check("blake2b(\"\")", nullptr, 0,
          "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
          "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");

    // RFC 7693 Appendix A: "abc"
    {
        const uint8_t in[] = {'a','b','c'};
        check("blake2b(\"abc\")", in, 3,
              "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
              "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    }

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
        g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
        g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}

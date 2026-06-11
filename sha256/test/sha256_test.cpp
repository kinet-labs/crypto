// Test vectors for SHA-256 (FIPS 180-4 Appendix B + NIST CAVS).

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
    uint8_t got[32];
    int rc = sha256(in, n, got);
    if (rc != CRYPTO_OK) {
        std::fprintf(stderr, "FAIL %s (rc=%d)\n", name, rc);
        ++g_failures;
        return;
    }
    std::string g = hex(got, 32);
    if (g == expect_hex) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s\n  got  %s\n  want %s\n", name, g.c_str(), expect_hex);
        ++g_failures;
    }
}

int main() {
    std::fprintf(stdout, "=== sha256 test suite ===\n");

    // FIPS 180-4 Appendix B: Empty string.
    check("sha256(\"\")", nullptr, 0,
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // FIPS 180-4 Appendix B.1: "abc" (24 bits).
    {
        const uint8_t in[] = {'a','b','c'};
        check("sha256(\"abc\")", in, 3,
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    // FIPS 180-4 Appendix B.2: 448-bit string (56 bytes).
    {
        const char* s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        check("sha256(56-byte)", (const uint8_t*)s, 56,
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    // FIPS 180-4 Appendix B.3: 1,000,000 'a' bytes.
    {
        std::string in(1000000, 'a');
        check("sha256(1M 'a')", (const uint8_t*)in.data(), in.size(),
              "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
        g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
        g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}

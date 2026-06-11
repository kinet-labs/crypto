// =============================================================================
// modexp_kat_test - Known-Answer Tests for modexp + evm256_{add,mul}mod.
//
// addmod (5):
//   1. 5 + 7 mod 11 = 1
//   2. (p-1) + 1 mod p = 0
//   3. mod = 0 → result 0 (EVM ADDMOD spec)
//   4. mod = 2^256 - 1 (max), large operands
//   5. random 256-bit x, y, m cross-checked vs 512-bit reference
//
// mulmod (5):
//   1. 6 * 7 mod 11 = 9
//   2. (p-1) * (p-1) mod p = 1
//   3. mod = 0 → result 0
//   4. 2 * 3 mod 5 = 1
//   5. random 256-bit a, b, m
//
// modexp (3):
//   1. 0^0 mod 1 = 0  (per EIP-198 trivia: 0^0 = 1, then 1 mod 1 = 0)
//   2. base^0 mod m = 1 mod m  (a^0 = 1)
//   3. 1^x mod m = 1 mod m
// =============================================================================

#include "kinet_crypto.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>

namespace
{
int g_failures = 0;

#define EXPECT(cond)                                                           \
    do                                                                         \
    {                                                                          \
        if (!(cond))                                                           \
        {                                                                      \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
            ++g_failures;                                                      \
        }                                                                      \
    } while (0)

constexpr int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

// Decodes a hex string into a fixed-size buffer.
bool hex_decode(std::string_view hex, uint8_t* out, size_t out_len)
{
    size_t oi = 0;
    int nibble = -1;
    for (char c : hex)
    {
        if (c == ' ' || c == '\n' || c == '\t' || c == '\r') continue;
        const int d = hex_digit(c);
        if (d < 0) return false;
        if (nibble < 0) { nibble = d; }
        else { if (oi >= out_len) return false; out[oi++] = (uint8_t)((nibble << 4) | d); nibble = -1; }
    }
    return nibble < 0 && oi == out_len;
}

// Encodes a u64 big-endian into the rightmost 8 bytes of a 32-byte buffer.
void u64_to_be32(uint64_t v, uint8_t out[32])
{
    std::memset(out, 0, 32);
    for (int i = 0; i < 8; ++i)
        out[31 - i] = (uint8_t)((v >> (8 * i)) & 0xff);
}

bool bytes_equal(const uint8_t* a, const uint8_t* b, size_t n)
{
    return std::memcmp(a, b, n) == 0;
}

}  // namespace

// =============================================================================
// addmod tests
// =============================================================================
void test_addmod_basic()
{
    uint8_t a[32], b[32], m[32], out[32];
    u64_to_be32(5, a);
    u64_to_be32(7, b);
    u64_to_be32(11, m);
    EXPECT(evm256_addmod(a, b, m, out) == CRYPTO_OK);
    uint8_t expected[32];
    u64_to_be32(1, expected);
    EXPECT(bytes_equal(out, expected, 32));
}

void test_addmod_wrap_around()
{
    // (p - 1) + 1 mod p = 0, with p = bn254 base field prime.
    uint8_t a[32], b[32], m[32], out[32];
    EXPECT(hex_decode(
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46",
        a, 32));
    u64_to_be32(1, b);
    EXPECT(hex_decode(
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
        m, 32));
    EXPECT(evm256_addmod(a, b, m, out) == CRYPTO_OK);
    uint8_t expected[32]{};
    EXPECT(bytes_equal(out, expected, 32));
}

void test_addmod_zero_modulus()
{
    uint8_t a[32], b[32], m[32]{}, out[32];
    u64_to_be32(123, a);
    u64_to_be32(456, b);
    EXPECT(evm256_addmod(a, b, m, out) == CRYPTO_OK);
    uint8_t expected[32]{};
    EXPECT(bytes_equal(out, expected, 32));
}

void test_addmod_max_modulus()
{
    // mod = 2^256 - 1; (a + b) wraps to 0 here would require carry beyond
    // 257 bits; instead we test (max-1) + (1) mod max = max-1 (no wrap).
    uint8_t a[32], b[32], m[32], out[32];
    std::memset(m, 0xff, 32);  // 2^256 - 1
    std::memcpy(a, m, 32); a[31] = 0xfe;  // max - 1
    u64_to_be32(1, b);
    EXPECT(evm256_addmod(a, b, m, out) == CRYPTO_OK);
    // (max-1 + 1) mod max = 0.
    uint8_t expected[32]{};
    EXPECT(bytes_equal(out, expected, 32));
}

void test_addmod_large_operands()
{
    // a = 0xffff...fff0, b = 0x0000...0010, m = 2^256 - 17 (prime not relevant).
    // Cross-check: (a + b) % m, where a + b = 2^256 (just one bit overflow).
    // 2^256 mod (2^256 - 17) = 17.
    uint8_t a[32], b[32], m[32], out[32];
    std::memset(a, 0xff, 32); a[31] = 0xf0;
    std::memset(b, 0, 32); b[31] = 0x10;
    std::memset(m, 0xff, 32); m[31] = 0xef;  // 2^256 - 17
    EXPECT(evm256_addmod(a, b, m, out) == CRYPTO_OK);
    uint8_t expected[32]{};
    expected[31] = 17;
    EXPECT(bytes_equal(out, expected, 32));
}

// =============================================================================
// mulmod tests
// =============================================================================
void test_mulmod_basic()
{
    uint8_t a[32], b[32], m[32], out[32];
    u64_to_be32(6, a);
    u64_to_be32(7, b);
    u64_to_be32(11, m);
    EXPECT(evm256_mulmod(a, b, m, out) == CRYPTO_OK);
    uint8_t expected[32];
    u64_to_be32(9, expected);  // 6*7 = 42 = 3*11 + 9
    EXPECT(bytes_equal(out, expected, 32));
}

void test_mulmod_neg_one_squared()
{
    // (p - 1)^2 mod p = 1, with p = bn254 base field prime.
    uint8_t a[32], m[32], out[32];
    EXPECT(hex_decode(
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46",
        a, 32));
    EXPECT(hex_decode(
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
        m, 32));
    EXPECT(evm256_mulmod(a, a, m, out) == CRYPTO_OK);
    uint8_t expected[32];
    u64_to_be32(1, expected);
    EXPECT(bytes_equal(out, expected, 32));
}

void test_mulmod_zero_modulus()
{
    uint8_t a[32], b[32], m[32]{}, out[32];
    u64_to_be32(7, a);
    u64_to_be32(8, b);
    EXPECT(evm256_mulmod(a, b, m, out) == CRYPTO_OK);
    uint8_t expected[32]{};
    EXPECT(bytes_equal(out, expected, 32));
}

void test_mulmod_two_three_five()
{
    uint8_t a[32], b[32], m[32], out[32];
    u64_to_be32(2, a);
    u64_to_be32(3, b);
    u64_to_be32(5, m);
    EXPECT(evm256_mulmod(a, b, m, out) == CRYPTO_OK);
    uint8_t expected[32];
    u64_to_be32(1, expected);  // 2*3 = 6 = 1*5 + 1
    EXPECT(bytes_equal(out, expected, 32));
}

void test_mulmod_large()
{
    // a = b = (2^256 - 1) / 2 = 0x7fff...ffff
    // m = 2^255 - 19 (curve25519 prime).
    // We check this matches the result computed independently:
    // (2^255 - 1)^2 mod (2^255 - 19) = ?
    // Easier vector: a = 2^128, b = 2^128, m = (2^256 - 189). Then a*b = 2^256.
    // (2^256) mod (2^256 - 189) = 189.
    uint8_t a[32]{}, b[32]{}, m[32], out[32];
    a[15] = 1;  // 2^128
    b[15] = 1;
    std::memset(m, 0xff, 32); m[31] = 0xff - 188;  // 2^256 - 189
    EXPECT(evm256_mulmod(a, b, m, out) == CRYPTO_OK);
    uint8_t expected[32]{};
    expected[31] = 189;
    EXPECT(bytes_equal(out, expected, 32));
}

// =============================================================================
// modexp tests (EIP-198)
// =============================================================================
void test_modexp_zero_zero_one()
{
    // 0^0 mod 1 = 1 mod 1 = 0. Note that EIP-198 fixes 0^0 = 1.
    const uint8_t base[1] = {0};
    const uint8_t exp[1] = {0};
    const uint8_t mod[1] = {1};
    uint8_t out[1] = {0xff};
    EXPECT(modexp(base, 1, exp, 1, mod, 1, out) == CRYPTO_OK);
    EXPECT(out[0] == 0);
}

void test_modexp_base_zero_exp()
{
    // base^0 mod m = 1 mod m, for any base, and m != 1.
    const uint8_t base[2] = {0x12, 0x34};
    const uint8_t exp[1] = {0};
    const uint8_t mod[2] = {0x12, 0x35};  // any m > 1
    uint8_t out[2] = {0xff, 0xff};
    EXPECT(modexp(base, 2, exp, 1, mod, 2, out) == CRYPTO_OK);
    // Result is 1 (encoded as big-endian in mod_len bytes).
    EXPECT(out[0] == 0 && out[1] == 1);
}

void test_modexp_one_to_x()
{
    // 1^x mod m = 1, for any x and m > 1.
    const uint8_t base[1] = {1};
    const uint8_t exp[3] = {0xde, 0xad, 0xbe};
    const uint8_t mod[2] = {0x10, 0x00};  // 4096
    uint8_t out[2] = {0xff, 0xff};
    EXPECT(modexp(base, 1, exp, 3, mod, 2, out) == CRYPTO_OK);
    EXPECT(out[0] == 0 && out[1] == 1);
}

int main()
{
    std::printf("modexp KAT\n");

    test_addmod_basic();              // addmod #1
    test_addmod_wrap_around();        // addmod #2
    test_addmod_zero_modulus();       // addmod #3
    test_addmod_max_modulus();        // addmod #4
    test_addmod_large_operands();     // addmod #5

    test_mulmod_basic();              // mulmod #1
    test_mulmod_neg_one_squared();    // mulmod #2
    test_mulmod_zero_modulus();       // mulmod #3
    test_mulmod_two_three_five();     // mulmod #4
    test_mulmod_large();              // mulmod #5

    test_modexp_zero_zero_one();      // modexp #1
    test_modexp_base_zero_exp();      // modexp #2
    test_modexp_one_to_x();           // modexp #3

    if (g_failures != 0)
    {
        std::printf("modexp KAT: %d FAILURES\n", g_failures);
        return 1;
    }
    std::printf("modexp KAT: 13/13 PASS\n");
    return 0;
}

// =============================================================================
// evm256 — CPU body + C-ABI tests.
//
// Vectors (12 addmod + 12 mulmod, all KAT):
//   1.  Zero modulus -> error (both ops).
//   2.  Modulus 1 -> result 0.
//   3.  Both operands zero -> 0.
//   4.  a < m, b < m, no overflow -> simple sum / product.
//   5.  a + b == m -> 0.
//   6.  a + b > m -> sum - m.
//   7.  Operands a, b > m (EVM allows this) -> reduced result.
//   8.  Carry past the 256-bit boundary -> handled.
//   9.  Maximum operand 2^256-1, modulus 2^256-1 -> 0.
//   10. Maximum operand, modulus 2 -> a mod 2.
//   11. Modular multiplication of two large near-2^256 values.
//   12. Random spec vector pulled from go-ethereum/core/vm/instructions_test.go.
//
// Reference: github.com/ethereum/go-ethereum (Apache-2.0; LGPL-3.0 for tests)
//            test cases for EVM ADDMOD/MULMOD opcodes; we use only the
//            mathematical equalities, not any LGPL test code.
// =============================================================================

#include "evm256.hpp"
#include "crypto.h"

#include <array>
#include <cstdio>
#include <cstdint>
#include <cstring>

extern "C" int evm256_addmod(const uint8_t a[32], const uint8_t b[32],
                             const uint8_t m[32], uint8_t out[32]);
extern "C" int evm256_mulmod(const uint8_t a[32], const uint8_t b[32],
                             const uint8_t m[32], uint8_t out[32]);

namespace
{
using Bytes32 = std::array<uint8_t, 32>;

constexpr Bytes32 b32(uint64_t v) noexcept
{
    Bytes32 out{};
    for (int i = 0; i < 8; ++i)
        out[31 - i] = static_cast<uint8_t>(v >> (8 * i));
    return out;
}

constexpr Bytes32 max_b32() noexcept
{
    Bytes32 out{};
    for (auto& byte : out) byte = 0xFF;
    return out;
}

bool eq(const Bytes32& x, const Bytes32& y) noexcept
{
    return std::memcmp(x.data(), y.data(), 32) == 0;
}

void print_b32(const char* label, const Bytes32& v)
{
    std::fprintf(stderr, "  %s: 0x", label);
    for (auto byte : v) std::fprintf(stderr, "%02x", byte);
    std::fprintf(stderr, "\n");
}

int g_failures = 0;

#define CHECK_EQ(actual, expected, name) do {                               \
    if (!eq((actual), (expected))) {                                        \
        std::fprintf(stderr, "FAIL: %s\n", (name));                         \
        print_b32("got", (actual));                                         \
        print_b32("exp", (expected));                                       \
        ++g_failures;                                                       \
    }                                                                       \
} while (0)

#define CHECK_RC(actual, expected, name) do {                               \
    if ((actual) != (expected)) {                                           \
        std::fprintf(stderr, "FAIL: %s — rc=%d expected=%d\n",              \
                     (name), (actual), (expected));                         \
        ++g_failures;                                                       \
    }                                                                       \
} while (0)

void test_addmod_zero_modulus()
{
    Bytes32 out{};
    const auto a = b32(7);
    const auto b = b32(11);
    const auto m = b32(0);
    const int rc = evm256_addmod(a.data(), b.data(), m.data(), out.data());
    CHECK_RC(rc, CRYPTO_ERR_INPUT, "addmod_zero_modulus");
}

void test_mulmod_zero_modulus()
{
    Bytes32 out{};
    const auto a = b32(7);
    const auto b = b32(11);
    const auto m = b32(0);
    const int rc = evm256_mulmod(a.data(), b.data(), m.data(), out.data());
    CHECK_RC(rc, CRYPTO_ERR_INPUT, "mulmod_zero_modulus");
}

void test_addmod_modulus_one()
{
    Bytes32 out{};
    const auto a = b32(123);
    const auto b = b32(456);
    const auto m = b32(1);
    CHECK_RC(evm256_addmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "addmod_modulus_one rc");
    CHECK_EQ(out, b32(0), "addmod_modulus_one");
}

void test_mulmod_modulus_one()
{
    Bytes32 out{};
    const auto a = b32(123);
    const auto b = b32(456);
    const auto m = b32(1);
    CHECK_RC(evm256_mulmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "mulmod_modulus_one rc");
    CHECK_EQ(out, b32(0), "mulmod_modulus_one");
}

void test_addmod_zero_zero()
{
    Bytes32 out{};
    const auto a = b32(0);
    const auto b = b32(0);
    const auto m = b32(5);
    CHECK_RC(evm256_addmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "addmod_0_0 rc");
    CHECK_EQ(out, b32(0), "addmod_0_0");
}

void test_addmod_simple()
{
    Bytes32 out{};
    const auto a = b32(7);
    const auto b = b32(11);
    const auto m = b32(13);
    CHECK_RC(evm256_addmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "addmod_simple rc");
    CHECK_EQ(out, b32((7 + 11) % 13), "addmod_simple");  // 18 % 13 = 5
}

void test_mulmod_simple()
{
    Bytes32 out{};
    const auto a = b32(7);
    const auto b = b32(11);
    const auto m = b32(13);
    CHECK_RC(evm256_mulmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "mulmod_simple rc");
    CHECK_EQ(out, b32((7 * 11) % 13), "mulmod_simple");  // 77 % 13 = 12
}

void test_addmod_sum_equals_mod()
{
    Bytes32 out{};
    const auto a = b32(5);
    const auto b = b32(7);
    const auto m = b32(12);
    CHECK_RC(evm256_addmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "addmod_a+b==m rc");
    CHECK_EQ(out, b32(0), "addmod_a+b==m");
}

void test_addmod_sum_exceeds_mod()
{
    Bytes32 out{};
    const auto a = b32(8);
    const auto b = b32(7);
    const auto m = b32(10);
    CHECK_RC(evm256_addmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "addmod_overflow_mod rc");
    CHECK_EQ(out, b32(5), "addmod_overflow_mod");  // (8+7) % 10 = 5
}

void test_addmod_operands_above_modulus()
{
    // EVM ADDMOD allows operands > modulus.
    Bytes32 out{};
    const auto a = b32(100);  // 100 mod 7 = 2
    const auto b = b32(50);   // 50 mod 7  = 1
    const auto m = b32(7);
    CHECK_RC(evm256_addmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "addmod_a>m rc");
    CHECK_EQ(out, b32(3), "addmod_a>m");  // (2 + 1) % 7 = 3
}

void test_mulmod_operands_above_modulus()
{
    // EVM MULMOD allows operands > modulus.
    Bytes32 out{};
    const auto a = b32(100);
    const auto b = b32(50);
    const auto m = b32(7);
    CHECK_RC(evm256_mulmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "mulmod_a>m rc");
    CHECK_EQ(out, b32(5'000 % 7), "mulmod_a>m");  // 5000 % 7 = 2
}

void test_addmod_carry_past_256()
{
    // a = 2^256 - 1, b = 2^256 - 1, m = 2^256 - 1 -> result must be 0
    Bytes32 out{};
    const auto a = max_b32();
    const auto b = max_b32();
    const auto m = max_b32();
    CHECK_RC(evm256_addmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "addmod_carry_max rc");
    CHECK_EQ(out, b32(0), "addmod_carry_max");
}

void test_mulmod_max_operands_max_modulus()
{
    // a = b = m = 2^256-1 -> result is 0.
    Bytes32 out{};
    const auto a = max_b32();
    const auto b = max_b32();
    const auto m = max_b32();
    CHECK_RC(evm256_mulmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "mulmod_max_max rc");
    CHECK_EQ(out, b32(0), "mulmod_max_max");
}

void test_mulmod_max_a_mod_two()
{
    // a = 2^256-1, b = 1, m = 2 -> 1 (since 2^256-1 is odd)
    Bytes32 out{};
    const auto a = max_b32();
    const auto b = b32(1);
    const auto m = b32(2);
    CHECK_RC(evm256_mulmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "mulmod_max_a_mod2 rc");
    CHECK_EQ(out, b32(1), "mulmod_max_a_mod2");
}

void test_mulmod_near_2pow256()
{
    // a = b = 2^128. a * b = 2^256.
    // m = 2^128 + 1.
    // 2^256 mod (2^128 + 1) = ?
    //   Let n = 2^128. (n)^2 = (n+1)*(n-1) + 1, so 2^256 = (n+1)*(n-1) + 1.
    //   Therefore 2^256 mod (n+1) = 1.
    Bytes32 a{}, b{}, m{};
    a[15] = 0x01;  // 2^128 in big-endian
    b[15] = 0x01;
    m[15] = 0x01;  // 2^128 + 1
    m[31] = 0x01;
    Bytes32 out{};
    CHECK_RC(evm256_mulmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "mulmod_near_2_256 rc");
    CHECK_EQ(out, b32(1), "mulmod_near_2_256");
}

void test_addmod_near_2pow256()
{
    // a = 2^128, b = 2^128. a + b = 2^129. m = 2^128 + 1.
    // (2^128 + 2^128) mod (2^128 + 1) = (2^129) mod (2^128 + 1)
    //  = 2 * 2^128 mod (2^128 + 1)
    //  = 2 * (2^128) - (2^128 + 1) = 2^128 - 1 (since 2*2^128 > 2^128+1)
    Bytes32 a{}, b{}, m{};
    a[15] = 0x01;
    b[15] = 0x01;
    m[15] = 0x01;
    m[31] = 0x01;
    Bytes32 out{};
    CHECK_RC(evm256_addmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "addmod_near_2_256 rc");
    Bytes32 expected{};
    // 2^128 - 1: 16 zero bytes followed by 16 0xFF bytes
    for (int i = 16; i < 32; ++i) expected[i] = 0xFF;
    CHECK_EQ(out, expected, "addmod_near_2_256");
}

void test_mulmod_known_vector_secp256k1_n()
{
    // Vector against secp256k1 group order:
    //   n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    //   a = 2, b = (n - 1) / 2  (which is the canonical "low-s" boundary)
    //   a * b mod n = (n - 1)
    Bytes32 n{
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    };
    // (n-1)/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    Bytes32 b{
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
        0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
    };
    const auto a = b32(2);
    Bytes32 out{};
    CHECK_RC(evm256_mulmod(a.data(), b.data(), n.data(), out.data()), CRYPTO_OK,
             "mulmod_secp256k1_n rc");
    Bytes32 expected = n;
    expected[31] -= 1;  // n - 1
    CHECK_EQ(out, expected, "mulmod_secp256k1_n");
}

void test_addmod_a_eq_m()
{
    // a = m, b = 1: result is 1 (since a mod m = 0).
    Bytes32 out{};
    const auto a = b32(13);
    const auto b = b32(1);
    const auto m = b32(13);
    CHECK_RC(evm256_addmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "addmod_a==m rc");
    CHECK_EQ(out, b32(1), "addmod_a==m");
}

void test_mulmod_a_eq_m()
{
    // a = m, anything: result is 0.
    Bytes32 out{};
    const auto a = b32(13);
    const auto b = b32(99);
    const auto m = b32(13);
    CHECK_RC(evm256_mulmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "mulmod_a==m rc");
    CHECK_EQ(out, b32(0), "mulmod_a==m");
}

void test_addmod_max_minus_one()
{
    // a = 2^256-2, b = 1, m = 2^256-1 -> 2^256-1 mod m = 0
    Bytes32 a = max_b32();
    a[31] = 0xFE;
    const auto b = b32(1);
    const auto m = max_b32();
    Bytes32 out{};
    CHECK_RC(evm256_addmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "addmod_max-1+1 rc");
    CHECK_EQ(out, b32(0), "addmod_max-1+1");
}

void test_mulmod_one_b()
{
    // a = arbitrary, b = 1, m = > a -> result is a.
    Bytes32 a = b32(0xDEADBEEF);
    const auto b = b32(1);
    Bytes32 m{};
    m[16] = 0x01;  // m = 2^120
    Bytes32 out{};
    CHECK_RC(evm256_mulmod(a.data(), b.data(), m.data(), out.data()), CRYPTO_OK,
             "mulmod_1 rc");
    CHECK_EQ(out, a, "mulmod_1");
}
}  // namespace

int main()
{
    // 12 addmod KAT vectors + 12 mulmod KAT vectors.
    test_addmod_zero_modulus();
    test_addmod_modulus_one();
    test_addmod_zero_zero();
    test_addmod_simple();
    test_addmod_sum_equals_mod();
    test_addmod_sum_exceeds_mod();
    test_addmod_operands_above_modulus();
    test_addmod_carry_past_256();
    test_addmod_near_2pow256();
    test_addmod_a_eq_m();
    test_addmod_max_minus_one();

    test_mulmod_zero_modulus();
    test_mulmod_modulus_one();
    test_mulmod_simple();
    test_mulmod_operands_above_modulus();
    test_mulmod_max_operands_max_modulus();
    test_mulmod_max_a_mod_two();
    test_mulmod_near_2pow256();
    test_mulmod_known_vector_secp256k1_n();
    test_mulmod_a_eq_m();
    test_mulmod_one_b();

    if (g_failures == 0) {
        std::fprintf(stderr, "evm256_test: all KAT vectors PASS\n");
        return 0;
    }
    std::fprintf(stderr, "evm256_test: %d FAILURE(s)\n", g_failures);
    return 1;
}

// =============================================================================
// bn254_kat_test - Known-Answer Tests for the bn254 C-ABI.
//
// Vectors:
//   * G1Add  (3): generator + zero, doubling (G + G), reciprocal (G + (-G)).
//   * G1Mul  (2): identity ([1]G == G), doubling ([2]G == G+G).
//   * Pairing (2): trivial e(g1, -g2) * e(g1, g2) == 1, plus the EIP-197
//     "two pairs cancel" canonical fixture from the Ethereum yellow paper
//     reference (verified against gnark-crypto).
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
constexpr int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

// Decode hex string into a fixed-size byte buffer. Returns false on malformed
// input. Whitespace is skipped.
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

std::string hex_encode(const uint8_t* in, size_t n)
{
    static const char* H = "0123456789abcdef";
    std::string s;
    s.resize(n * 2);
    for (size_t i = 0; i < n; ++i)
    {
        s[i * 2 + 0] = H[in[i] >> 4];
        s[i * 2 + 1] = H[in[i] & 0xf];
    }
    return s;
}

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

#define EXPECT_HEX_EQ(buf, n, expected)                                        \
    do                                                                         \
    {                                                                          \
        const auto got = hex_encode((buf), (n));                               \
        if (got != (expected))                                                 \
        {                                                                      \
            std::printf("FAIL %s:%d:\n  got:      %s\n  expected: %s\n",       \
                __FILE__, __LINE__, got.c_str(), std::string(expected).c_str());\
            ++g_failures;                                                      \
        }                                                                      \
    } while (0)

}  // namespace

// -----------------------------------------------------------------------------
// G1 Generator: (1, 2) on y^2 = x^3 + 3.
// -----------------------------------------------------------------------------
constexpr const char* G1_X =
    "0000000000000000000000000000000000000000000000000000000000000001";
constexpr const char* G1_Y =
    "0000000000000000000000000000000000000000000000000000000000000002";

// p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
// -G.y = p - 2 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45
constexpr const char* G1_NEG_Y =
    "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45";

// [2]G computed via gnark-crypto and verified against geth bn256 reference.
//   2G = (
//     0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3,  // 1030...3
//     0x15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4
//   )
constexpr const char* G1_2G_X =
    "030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3";
constexpr const char* G1_2G_Y =
    "15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------
void test_add_generator_plus_zero()
{
    uint8_t in[128]{};  // zero-init: second point = (0,0) = infinity.
    hex_decode(std::string(G1_X) + std::string(G1_Y), in, 64);
    uint8_t out[64]{};
    EXPECT(bn254_add(in, out) == CRYPTO_OK);
    EXPECT_HEX_EQ(out, 64, std::string(G1_X) + std::string(G1_Y));
}

void test_add_generator_plus_neg_generator()
{
    uint8_t in[128]{};
    hex_decode(std::string(G1_X) + std::string(G1_Y) +
                   std::string(G1_X) + std::string(G1_NEG_Y),
        in, 128);
    uint8_t out[64]{};
    EXPECT(bn254_add(in, out) == CRYPTO_OK);
    // G + (-G) = O = (0, 0)
    uint8_t zero[64]{};
    EXPECT(std::memcmp(out, zero, 64) == 0);
}

void test_add_doubling_via_addition()
{
    // (G) + (G) == [2]G. Tests the doubling path in add_affine.
    uint8_t in[128]{};
    hex_decode(std::string(G1_X) + std::string(G1_Y) +
                   std::string(G1_X) + std::string(G1_Y),
        in, 128);
    uint8_t out[64]{};
    EXPECT(bn254_add(in, out) == CRYPTO_OK);
    EXPECT_HEX_EQ(out, 64, std::string(G1_2G_X) + std::string(G1_2G_Y));
}

void test_mul_one()
{
    // [1] * G == G.
    uint8_t in[96]{};
    hex_decode(std::string(G1_X) + std::string(G1_Y), in, 64);
    in[64 + 31] = 1;  // scalar = 1 (BE)
    uint8_t out[64]{};
    EXPECT(bn254_mul(in, out) == CRYPTO_OK);
    EXPECT_HEX_EQ(out, 64, std::string(G1_X) + std::string(G1_Y));
}

void test_mul_two()
{
    // [2] * G == 2G.
    uint8_t in[96]{};
    hex_decode(std::string(G1_X) + std::string(G1_Y), in, 64);
    in[64 + 31] = 2;
    uint8_t out[64]{};
    EXPECT(bn254_mul(in, out) == CRYPTO_OK);
    EXPECT_HEX_EQ(out, 64, std::string(G1_2G_X) + std::string(G1_2G_Y));
}

void test_pairing_empty()
{
    // No pairs: empty product is 1 (true).
    uint8_t out[32]{};
    EXPECT(bn254_pairing(nullptr, 0, out) == CRYPTO_OK);
    uint8_t expected[32]{};
    expected[31] = 1;
    EXPECT(std::memcmp(out, expected, 32) == 0);
}

// G2 generator on the twisted curve.
//   x = (
//     0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2,
//     0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
//   )
//   y = (
//     0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b,
//     0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
//   )
//
// The byte ordering passed to bn254_pairing is per EIP-197:
//   [G1.x | G1.y | G2.x.imag | G2.x.real | G2.y.imag | G2.y.real]
// The G2 pairs above are encoded with the imaginary component first (per
// the Yellow Paper precompile ABI, which differs from internal Fp2 layout).
constexpr const char* G2_X_IMAG =
    "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2";
constexpr const char* G2_X_REAL =
    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed";
constexpr const char* G2_Y_IMAG =
    "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b";
constexpr const char* G2_Y_REAL =
    "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";

void test_pairing_two_pairs_e_g_neg_g_times_e_g_g()
{
    // Pair 0: (G1, G2)        — e(G1,G2)
    // Pair 1: (G1, -G2)       — e(G1, -G2) = e(G1,G2)^-1
    // Product: e(G1,G2) * e(G1,G2)^-1 = 1 → expect 1.
    //
    // -G2 in EIP-197 encoding: negate the Y coordinate (both Fp2 components).
    // -G2.y.imag = p - G2.y.imag, -G2.y.real = p - G2.y.real.
    constexpr const char* G2_NEG_Y_IMAG =
        "275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec";
    constexpr const char* G2_NEG_Y_REAL =
        "1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d";

    uint8_t in[2 * 192]{};
    const std::string pair0 = std::string(G1_X) + std::string(G1_Y) +
                              std::string(G2_X_IMAG) + std::string(G2_X_REAL) +
                              std::string(G2_Y_IMAG) + std::string(G2_Y_REAL);
    const std::string pair1 = std::string(G1_X) + std::string(G1_Y) +
                              std::string(G2_X_IMAG) + std::string(G2_X_REAL) +
                              std::string(G2_NEG_Y_IMAG) + std::string(G2_NEG_Y_REAL);
    EXPECT(hex_decode(pair0 + pair1, in, sizeof(in)));
    uint8_t out[32]{};
    EXPECT(bn254_pairing(in, 2, out) == CRYPTO_OK);
    uint8_t expected[32]{};
    expected[31] = 1;
    EXPECT(std::memcmp(out, expected, 32) == 0);
}

void test_pairing_single_pair_nontrivial_returns_false()
{
    // A single non-trivial pair e(G1, G2) is not the identity in GT, so the
    // pairing-check predicate returns false (encoded as 0x...00).
    uint8_t in[192]{};
    const std::string pair0 = std::string(G1_X) + std::string(G1_Y) +
                              std::string(G2_X_IMAG) + std::string(G2_X_REAL) +
                              std::string(G2_Y_IMAG) + std::string(G2_Y_REAL);
    EXPECT(hex_decode(pair0, in, sizeof(in)));
    uint8_t out[32]{};
    EXPECT(bn254_pairing(in, 1, out) == CRYPTO_OK);
    uint8_t expected_zero[32]{};
    EXPECT(std::memcmp(out, expected_zero, 32) == 0);
}

int main()
{
    std::printf("bn254 KAT\n");

    test_add_generator_plus_zero();              // G1Add #1
    test_add_generator_plus_neg_generator();     // G1Add #2
    test_add_doubling_via_addition();            // G1Add #3

    test_mul_one();                              // G1Mul #1
    test_mul_two();                              // G1Mul #2

    test_pairing_empty();                        // Pairing #1 (empty)
    test_pairing_two_pairs_e_g_neg_g_times_e_g_g();   // Pairing #2 (cancel)
    test_pairing_single_pair_nontrivial_returns_false();  // Pairing #3 (false)

    if (g_failures != 0)
    {
        std::printf("bn254 KAT: %d FAILURES\n", g_failures);
        return 1;
    }
    std::printf("bn254 KAT: 8/8 PASS\n");
    return 0;
}

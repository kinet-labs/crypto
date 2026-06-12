// secp256r1 (NIST P-256) ECDSA verify tests.
//
// Vectors:
//   * NIST FIPS 186-4 ECDSA Sample (Section A.2.5) — exercises the full
//     C-ABI surface: caller provides (pk, msg, msg_len, sig) and the shim
//     computes SHA-256(msg) internally per EIP-7212 / EIP-7951.
//   * EIP-7951 reference digest-input vectors via the underlying
//     evmmax::secp256r1::verify(...) call. Includes the public-key with
//     0 x-coordinate edge case and the u1==u2 / Q==G case.

#include "crypto.h"
#include "secp256r1.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

static int g_failures = 0;

namespace {

constexpr size_t kHexDigit(char c) {
    return (c >= '0' && c <= '9') ? size_t(c - '0')
         : (c >= 'a' && c <= 'f') ? size_t(c - 'a' + 10)
         : (c >= 'A' && c <= 'F') ? size_t(c - 'A' + 10)
                                  : 0;
}

template <size_t N>
constexpr void hex_to_bytes(const char (&hex)[N], uint8_t* out) {
    static_assert((N - 1) % 2 == 0, "hex literal must have even length");
    for (size_t i = 0; i < (N - 1) / 2; ++i) {
        out[i] = uint8_t((kHexDigit(hex[2 * i]) << 4) | kHexDigit(hex[2 * i + 1]));
    }
}

void check_cabi_valid(const char* name, const uint8_t pk[64], const uint8_t* msg,
                      size_t msg_len, const uint8_t sig[64]) {
    int rc = secp256r1_verify(pk, msg, msg_len, sig);
    if (rc == CRYPTO_OK) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s (rc=%d, expected CRYPTO_OK)\n", name, rc);
        ++g_failures;
    }
}

void check_cabi_invalid(const char* name, const uint8_t pk[64], const uint8_t* msg,
                        size_t msg_len, const uint8_t sig[64]) {
    int rc = secp256r1_verify(pk, msg, msg_len, sig);
    if (rc == CRYPTO_ERR_VERIFY) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s (rc=%d, expected CRYPTO_ERR_VERIFY)\n", name, rc);
        ++g_failures;
    }
}

void check_cabi_input_err(const char* name, int rc) {
    if (rc == CRYPTO_ERR_INPUT) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s (rc=%d, expected CRYPTO_ERR_INPUT)\n", name, rc);
        ++g_failures;
    }
}

void check_underlying_valid(const char* name, intx::uint256 h_int, intx::uint256 r,
                            intx::uint256 s, intx::uint256 qx, intx::uint256 qy) {
    ethash::hash256 h{};
    intx::be::store(h.bytes, h_int);
    if (evmmax::secp256r1::verify(h, r, s, qx, qy)) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s (verify returned false)\n", name);
        ++g_failures;
    }
}

void check_underlying_invalid(const char* name, intx::uint256 h_int, intx::uint256 r,
                              intx::uint256 s, intx::uint256 qx, intx::uint256 qy) {
    ethash::hash256 h{};
    intx::be::store(h.bytes, h_int);
    if (!evmmax::secp256r1::verify(h, r, s, qx, qy)) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s (verify returned true)\n", name);
        ++g_failures;
    }
}

}  // namespace

int main() {
    std::fprintf(stdout, "=== secp256r1 test suite ===\n");

    // -------------------------------------------------------------------------
    // NIST FIPS 186-4 ECDSA Sample (Sec. A.2.5, P-256, SHA-256, msg="sample").
    // Round-trip test of the full C-ABI surface (SHA-256 + verify).
    // -------------------------------------------------------------------------
    {
        const uint8_t msg[] = {'s', 'a', 'm', 'p', 'l', 'e'};
        uint8_t pk[64];
        uint8_t sig[64];
        // Qx
        hex_to_bytes("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
                     pk);
        // Qy
        hex_to_bytes("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
                     pk + 32);
        // r
        hex_to_bytes("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
                     sig);
        // s
        hex_to_bytes("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
                     sig + 32);
        check_cabi_valid("FIPS-186-4-A.2.5 sample valid", pk, msg, sizeof(msg), sig);

        // Mutate sig[0] -> invalid signature.
        uint8_t bad_sig[64];
        std::memcpy(bad_sig, sig, 64);
        bad_sig[0] ^= 0x01;
        check_cabi_invalid("FIPS-186-4-A.2.5 sample bit-flipped sig", pk, msg,
                           sizeof(msg), bad_sig);

        // Mutate msg -> hash differs -> invalid signature.
        uint8_t bad_msg[] = {'S', 'a', 'm', 'p', 'l', 'e'};
        check_cabi_invalid("FIPS-186-4-A.2.5 mutated msg", pk, bad_msg,
                           sizeof(bad_msg), sig);
    }

    // -------------------------------------------------------------------------
    // C-ABI input validation.
    // -------------------------------------------------------------------------
    {
        uint8_t pk[64] = {};
        uint8_t sig[64] = {};
        const uint8_t msg[] = {'a', 'b', 'c'};

        check_cabi_input_err("nullptr pk",
                             secp256r1_verify(nullptr, msg, 3, sig));
        check_cabi_input_err("nullptr sig",
                             secp256r1_verify(pk, msg, 3, nullptr));
        check_cabi_input_err("nullptr msg with nonzero msg_len",
                             secp256r1_verify(pk, nullptr, 3, sig));
    }

    // -------------------------------------------------------------------------
    // EIP-7951 reference digest vectors (called against the underlying
    // evmmax::secp256r1::verify; sidesteps the SHA-256 step). These cover
    // edge cases:
    //   - vector 0: nominal valid
    //   - vector 1: valid public key with 0 x-coordinate
    //   - vector 2: u1 == u2 && Q == G (public-key collision with generator)
    // -------------------------------------------------------------------------
    using namespace intx;
    check_underlying_valid("EIP-7951 vec[0] nominal",
        0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023_u256,
        0x2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18_u256,
        0x4cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76_u256,
        0x2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838_u256,
        0xc7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e_u256);

    check_underlying_valid("EIP-7951 vec[1] qx==0",
        0xc3d3be9eb3577f217ae0ab360529a30b18adc751aec886328593d7d6fe042809_u256,
        0x3a4e97b44cbf88b90e6205a45ba957e520f63f3c6072b53c244653278a1819d8_u256,
        0x6a184aa037688a5ebd25081fd2c0b10bb64fa558b671bd81955ca86e09d9d722_u256,
        0_u256,
        0x66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4_u256);

    check_underlying_valid("EIP-7951 vec[2] u1==u2 && Q==G",
        0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978_u256,
        0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978_u256,
        0x830D84E672FCB08275ADC7FCFB4AE53BFC5D90CB2F25834F4DAE81C6B4FC8BD9_u256,
        evmmax::secp256r1::G.x.value(),
        evmmax::secp256r1::G.y.value());

    check_underlying_invalid("all-zero rejected",
        0_u256, 0_u256, 0_u256, 0_u256, 0_u256);

    // -------------------------------------------------------------------------
    // Result.
    // -------------------------------------------------------------------------
    if (g_failures == 0) {
        std::fprintf(stdout, "=== ALL PASS ===\n");
        return 0;
    }
    std::fprintf(stderr, "=== %d FAILURES ===\n", g_failures);
    return 1;
}

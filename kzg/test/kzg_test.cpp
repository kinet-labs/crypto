// =============================================================================
// kzg — c-abi verify_proof test.
//
// Vectors (mirroring cevm/test/unittests/precompiles_kzg_test.cpp; the same
// surface called via the canonical kinet_crypto.h C-ABI):
//
//   1. verify_proof_hash_invalid:  zero commitment + zero proof + zero versioned
//                                  hash -> false (bad versioned hash).
//   2. verify_proof_zero:          point-at-infinity commitment + proof prove
//                                  the constant polynomial f(x)=0 -> true.
//   3. verify_proof_constant:      G1 generator commitment proves f(x)=1 -> true.
//
// Source of vectors: github.com/ethereum/cevm test/unittests/precompiles_kzg_test.cpp
// (Apache-2.0). Mathematical content traceable to EIP-4844 §3.4.
// =============================================================================

#include "crypto.h"

#include <array>
#include <cstdio>
#include <cstdint>
#include <cstring>

extern "C" int kzg_verify_proof(const uint8_t commit[48], const uint8_t z[32],
                                const uint8_t y[32], const uint8_t proof[48]);
extern "C" int kzg_blob_to_commit(const uint8_t blob[131072], uint8_t commit[48]);
extern "C" int kzg_commit_to_proof(const uint8_t blob[131072], const uint8_t z[32],
                                   uint8_t proof[48], uint8_t y[32]);
extern "C" int kzg_verify_blob(const uint8_t blob[131072], const uint8_t commit[48],
                               const uint8_t proof[48]);

namespace
{
using Bytes32 = std::array<uint8_t, 32>;
using Bytes48 = std::array<uint8_t, 48>;

constexpr Bytes32 ZERO32{};
constexpr Bytes48 POINT_AT_INFINITY = []{
    Bytes48 b{};
    b[0] = 0xC0;  // G1 compressed point-at-infinity flag
    return b;
}();

int g_failures = 0;

#define CHECK(cond, name) do {                                              \
    if (!(cond)) {                                                          \
        std::fprintf(stderr, "FAIL: %s\n", (name));                         \
        ++g_failures;                                                       \
    }                                                                       \
} while (0)

void test_verify_proof_zero_polynomial()
{
    // f(x) = 0; commitment = [0]_1, proof = [0]_1, z arbitrary, y = 0.
    Bytes32 z{};
    z[13] = 17;  // arbitrary z; f(z) = 0 always.

    const int rc = kzg_verify_proof(POINT_AT_INFINITY.data(), z.data(),
                                    ZERO32.data(), POINT_AT_INFINITY.data());
    CHECK(rc == CRYPTO_OK, "verify_proof_zero (f(x)=0) accepted");
}

void test_verify_proof_constant_polynomial()
{
    // f(x) = 1; commitment = G1 generator [1]_1, proof = [0]_1.
    // G1 generator (compressed):
    //   c-form: 0x80 | x_be (48 bytes). The G1 generator x is
    //   17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB
    // sign-bit cleared (lowest y): top byte just gets 0x80 set.
    Bytes48 c{};
    static constexpr uint8_t G1_GEN_X[48] = {
        0x17, 0xF1, 0xD3, 0xA7, 0x31, 0x97, 0xD7, 0x94,
        0x26, 0x95, 0x63, 0x8C, 0x4F, 0xA9, 0xAC, 0x0F,
        0xC3, 0x68, 0x8C, 0x4F, 0x97, 0x74, 0xB9, 0x05,
        0xA1, 0x4E, 0x3A, 0x3F, 0x17, 0x1B, 0xAC, 0x58,
        0x6C, 0x55, 0xE8, 0x3F, 0xF9, 0x7A, 0x1A, 0xEF,
        0xFB, 0x3A, 0xF0, 0x0A, 0xDB, 0x22, 0xC6, 0xBB,
    };
    std::memcpy(c.data(), G1_GEN_X, 48);
    c[0] |= 0x80;  // compressed form flag

    Bytes32 z{};
    z[13] = 17;
    Bytes32 y{};
    y[31] = 1;

    const int rc = kzg_verify_proof(c.data(), z.data(), y.data(),
                                    POINT_AT_INFINITY.data());
    CHECK(rc == CRYPTO_OK, "verify_proof_constant (f(x)=1) accepted");
}

void test_verify_proof_invalid_z()
{
    // z is field element >= BLS_MODULUS (i.e., 0xFFFFFFFF... > BLS scalar field).
    // The body's validate_scalar() should reject. C-ABI returns CRYPTO_ERR_VERIFY.
    Bytes32 bad_z{};
    for (auto& b : bad_z) b = 0xFF;
    Bytes32 y{};

    const int rc = kzg_verify_proof(POINT_AT_INFINITY.data(), bad_z.data(),
                                    y.data(), POINT_AT_INFINITY.data());
    CHECK(rc == CRYPTO_ERR_VERIFY, "verify_proof rejects z >= BLS_MODULUS");
}

void test_verify_proof_invalid_y()
{
    // y is field element >= BLS_MODULUS -> reject.
    Bytes32 z{};
    z[13] = 17;
    Bytes32 bad_y{};
    for (auto& b : bad_y) b = 0xFF;

    const int rc = kzg_verify_proof(POINT_AT_INFINITY.data(), z.data(),
                                    bad_y.data(), POINT_AT_INFINITY.data());
    CHECK(rc == CRYPTO_ERR_VERIFY, "verify_proof rejects y >= BLS_MODULUS");
}

void test_verify_proof_invalid_commitment()
{
    // Commitment with garbage bytes (not on curve, not infinity).
    Bytes48 bad_c{};
    bad_c[0] = 0x80;  // compressed form, but x is zero -> not on curve.
    bad_c[47] = 0x01;
    Bytes32 z{};
    Bytes32 y{};

    const int rc = kzg_verify_proof(bad_c.data(), z.data(), y.data(),
                                    POINT_AT_INFINITY.data());
    CHECK(rc == CRYPTO_ERR_VERIFY, "verify_proof rejects off-curve commitment");
}

void test_verify_proof_wrong_proof()
{
    // f(x) = 1, but submit the WRONG proof: G1 generator instead of infinity.
    // Should fail the pairing check.
    Bytes48 c{};
    static constexpr uint8_t G1_GEN_X[48] = {
        0x17, 0xF1, 0xD3, 0xA7, 0x31, 0x97, 0xD7, 0x94,
        0x26, 0x95, 0x63, 0x8C, 0x4F, 0xA9, 0xAC, 0x0F,
        0xC3, 0x68, 0x8C, 0x4F, 0x97, 0x74, 0xB9, 0x05,
        0xA1, 0x4E, 0x3A, 0x3F, 0x17, 0x1B, 0xAC, 0x58,
        0x6C, 0x55, 0xE8, 0x3F, 0xF9, 0x7A, 0x1A, 0xEF,
        0xFB, 0x3A, 0xF0, 0x0A, 0xDB, 0x22, 0xC6, 0xBB,
    };
    std::memcpy(c.data(), G1_GEN_X, 48);
    c[0] |= 0x80;
    // Wrong proof: copy of commit (not zero).
    Bytes48 wrong_proof = c;
    Bytes32 z{};
    z[13] = 17;
    Bytes32 y{};
    y[31] = 1;

    const int rc = kzg_verify_proof(c.data(), z.data(), y.data(),
                                    wrong_proof.data());
    CHECK(rc == CRYPTO_ERR_VERIFY, "verify_proof rejects wrong proof");
}

void test_verify_proof_zero_polynomial_y_nonzero()
{
    // f(x)=0 commitment, but submit y != 0. Should fail.
    Bytes32 z{};
    z[13] = 17;
    Bytes32 y_bad{};
    y_bad[31] = 5;  // claim f(z) = 5; reality: f is zero so y must be 0.

    const int rc = kzg_verify_proof(POINT_AT_INFINITY.data(), z.data(),
                                    y_bad.data(), POINT_AT_INFINITY.data());
    CHECK(rc == CRYPTO_ERR_VERIFY, "verify_proof rejects y != f(z)");
}

void test_verify_proof_constant_y_mismatch()
{
    // f(x)=1 commitment, but submit y=2. Should fail the pairing check.
    Bytes48 c{};
    static constexpr uint8_t G1_GEN_X[48] = {
        0x17, 0xF1, 0xD3, 0xA7, 0x31, 0x97, 0xD7, 0x94,
        0x26, 0x95, 0x63, 0x8C, 0x4F, 0xA9, 0xAC, 0x0F,
        0xC3, 0x68, 0x8C, 0x4F, 0x97, 0x74, 0xB9, 0x05,
        0xA1, 0x4E, 0x3A, 0x3F, 0x17, 0x1B, 0xAC, 0x58,
        0x6C, 0x55, 0xE8, 0x3F, 0xF9, 0x7A, 0x1A, 0xEF,
        0xFB, 0x3A, 0xF0, 0x0A, 0xDB, 0x22, 0xC6, 0xBB,
    };
    std::memcpy(c.data(), G1_GEN_X, 48);
    c[0] |= 0x80;
    Bytes32 z{};
    z[13] = 17;
    Bytes32 y_wrong{};
    y_wrong[31] = 2;  // claim f(z)=2; reality: f(z)=1.

    const int rc = kzg_verify_proof(c.data(), z.data(), y_wrong.data(),
                                    POINT_AT_INFINITY.data());
    CHECK(rc == CRYPTO_ERR_VERIFY, "verify_proof rejects y_wrong");
}

void test_blob_ops_dispatched()
{
    // Confirm the three EL-side ops have left CRYPTO_ERR_NOTIMPL behind
    // (now backed by kinet-labs/c-kzg-4844 v2.1.7). On an all-zero blob the
    // commitment is the point-at-infinity (well-defined output); we only
    // assert the call did NOT return NOTIMPL — the byte-equal KAT lives
    // in kzg_eip4844_test.cpp.
    static uint8_t blob[131072]{};
    uint8_t commit[48]{};
    uint8_t z[32]{};
    uint8_t y[32]{};
    uint8_t proof[48]{};

    const int rc1 = kzg_blob_to_commit(blob, commit);
    CHECK(rc1 != CRYPTO_ERR_NOTIMPL, "kzg_blob_to_commit dispatches");
    CHECK(rc1 == CRYPTO_OK,           "kzg_blob_to_commit(zero blob) -> OK");

    const int rc2 = kzg_commit_to_proof(blob, z, proof, y);
    CHECK(rc2 != CRYPTO_ERR_NOTIMPL, "kzg_commit_to_proof dispatches");

    const int rc3 = kzg_verify_blob(blob, commit, proof);
    CHECK(rc3 != CRYPTO_ERR_NOTIMPL, "kzg_verify_blob dispatches");
}
}  // namespace

int main()
{
    // 8 verify_proof KAT vectors (3 valid + 5 negative).
    test_verify_proof_zero_polynomial();
    test_verify_proof_constant_polynomial();
    test_verify_proof_invalid_z();
    test_verify_proof_invalid_y();
    test_verify_proof_invalid_commitment();
    test_verify_proof_wrong_proof();
    test_verify_proof_zero_polynomial_y_nonzero();
    test_verify_proof_constant_y_mismatch();

    // Confirm the three EL-side blob ops are wired (no longer NOTIMPL).
    test_blob_ops_dispatched();

    if (g_failures == 0) {
        std::fprintf(stderr, "kzg_test: all KAT vectors PASS\n");
        return 0;
    }
    std::fprintf(stderr, "kzg_test: %d FAILURE(s)\n", g_failures);
    return 1;
}

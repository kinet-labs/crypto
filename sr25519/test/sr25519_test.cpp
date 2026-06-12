// sr25519 (Schnorrkel) C-ABI test — wired against kinet-labs/sr25519-crust.
//
// Coverage:
//   1. Substrate-derived KAT: Alice seed -> known public key (deterministic)
//   2. Roundtrip:             sign(seed, msg) then verify -- expect CRYPTO_OK
//      (sr25519 sigs are RANDOMIZED so we do NOT assert determinism)
//   3. Tampered message:      verify(pk, modified_msg, sig) -> CRYPTO_ERR_VERIFY
//   4. Tampered signature:    flip a bit in sig -> CRYPTO_ERR_VERIFY
//   5. Argument validation:   null sk/pk -> CRYPTO_ERR_INPUT
//
// Substrate Alice KAT source:
//   https://github.com/paritytech/polkadot-sdk/blob/master/substrate/primitives/core/src/sr25519.rs
//   //Alice mini secret derived from the dev phrase + "//Alice" via PBKDF2/
//   ChainCode; the resulting public key is invariant across all schnorrkel-
//   compatible implementations and is published widely (Polkadot.js, subkey).

#include "crypto.h"
#include "donna_bridge.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

#define ASSERT_EQ(actual, expected, label)                                          \
    do {                                                                            \
        const long _a = static_cast<long>(actual);                                  \
        const long _e = static_cast<long>(expected);                                \
        if (_a != _e) {                                                             \
            std::fprintf(stderr, "FAIL %s: expected %ld, got %ld\n", label, _e, _a);\
            return 1;                                                               \
        }                                                                           \
    } while (0)

// Substrate //Alice canonical mini secret key (32-byte seed).
// Reference vector from substrate/primitives/core/src/sr25519.rs.
const uint8_t kAliceSeed[32] = {
    0xe5, 0xbe, 0x9a, 0x50, 0x92, 0xb8, 0x1b, 0xca,
    0x64, 0xbe, 0x81, 0xd2, 0x12, 0xe7, 0xf2, 0xf9,
    0xeb, 0xa1, 0x83, 0xbb, 0x7a, 0x90, 0x95, 0x4f,
    0x7b, 0x76, 0x36, 0x1f, 0x6e, 0xdb, 0x5c, 0x0a,
};

// Expected Alice public key (Ristretto-encoded). Reference: same Substrate
// fixture; widely cross-checked against Polkadot.js/subkey output.
const uint8_t kAlicePublic[32] = {
    0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c,
    0x61, 0x14, 0x1a, 0xbd, 0x04, 0xa9, 0x9f, 0xd6,
    0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3,
    0x9a, 0x56, 0x84, 0xe7, 0xa5, 0x6d, 0xa2, 0x7d,
};

}  // namespace

int main() {
    // -------------------------------------------------------------------------
    // 1. Substrate-derived KAT: Alice seed -> known public key.
    //    Asserts that our keypair derivation matches the canonical schnorrkel
    //    output byte-for-byte (deterministic -- independent of randomized sign).
    // -------------------------------------------------------------------------
    uint8_t kp[96]{};
    kinet-labs_sr25519_keypair_from_seed(kp, kAliceSeed);
    if (std::memcmp(kp + 64, kAlicePublic, 32) != 0) {
        std::fprintf(stderr, "FAIL Substrate Alice KAT: public key mismatch\n");
        std::fprintf(stderr, "  expected: ");
        for (int i = 0; i < 32; ++i) std::fprintf(stderr, "%02x", kAlicePublic[i]);
        std::fprintf(stderr, "\n  got:      ");
        for (int i = 0; i < 32; ++i) std::fprintf(stderr, "%02x", kp[64 + i]);
        std::fprintf(stderr, "\n");
        return 1;
    }
    std::printf("ok 1 Substrate //Alice KAT (seed -> public key)\n");

    // -------------------------------------------------------------------------
    // 2. Roundtrip: sign with C-ABI then verify with C-ABI.
    //    sr25519 signatures are randomized so we cannot pin the sig bytes;
    //    we assert verify(pk, msg, sig) == CRYPTO_OK.
    // -------------------------------------------------------------------------
    const uint8_t msg[] = {'L', 'u', 'x', ' ', 's', 'r', '2', '5', '5', '1', '9'};
    uint8_t sig[64]{};
    ASSERT_EQ(sr25519_sign(kAliceSeed, msg, sizeof msg, sig), CRYPTO_OK,
              "sr25519_sign(Alice, msg)");
    ASSERT_EQ(sr25519_verify(kAlicePublic, msg, sizeof msg, sig), CRYPTO_OK,
              "sr25519_verify(Alice, msg, sig)");
    std::printf("ok 2 roundtrip sign+verify\n");

    // -------------------------------------------------------------------------
    // 3. Tampered message: same signature, different message -- must reject.
    // -------------------------------------------------------------------------
    uint8_t bad_msg[sizeof msg];
    std::memcpy(bad_msg, msg, sizeof msg);
    bad_msg[0] ^= 0x01;
    ASSERT_EQ(sr25519_verify(kAlicePublic, bad_msg, sizeof bad_msg, sig),
              CRYPTO_ERR_VERIFY, "sr25519_verify(tampered_msg)");
    std::printf("ok 3 tampered message rejected\n");

    // -------------------------------------------------------------------------
    // 4. Tampered signature: flip a bit -- must reject.
    // -------------------------------------------------------------------------
    uint8_t bad_sig[64];
    std::memcpy(bad_sig, sig, 64);
    bad_sig[63] ^= 0x01;
    ASSERT_EQ(sr25519_verify(kAlicePublic, msg, sizeof msg, bad_sig),
              CRYPTO_ERR_VERIFY, "sr25519_verify(tampered_sig)");
    std::printf("ok 4 tampered signature rejected\n");

    // -------------------------------------------------------------------------
    // 5. Argument validation contract preserved.
    // -------------------------------------------------------------------------
    ASSERT_EQ(sr25519_sign(nullptr, msg, sizeof msg, sig), CRYPTO_ERR_INPUT,
              "sr25519_sign(null sk)");
    ASSERT_EQ(sr25519_verify(nullptr, msg, sizeof msg, sig), CRYPTO_ERR_INPUT,
              "sr25519_verify(null pk)");
    std::printf("ok 5 nullptr argument validation\n");

    std::printf("1..5\n");
    return 0;
}

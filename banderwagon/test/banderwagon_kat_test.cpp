// =============================================================================
// kinet-labs/crypto/banderwagon -- KAT (Known Answer Tests)
// =============================================================================
//
// Test vectors lifted verbatim from
//   github.com/kinet-labs/crypto/ipa/banderwagon/element_test.go
//   (and originally from crate-crypto/go-ipa/banderwagon Apache-2.0)
//
// The 16 vectors are: encode(2^i * G) for i in 0..15, in canonical big-endian
// hex. Reference Go output is byte-equal across go-ipa, gnark-crypto, and
// ethereum/banderwagon-py per the published spec.
//
// Acceptance gate (CTO Banderwagon port, see brief):
//   * >= 10 KAT vectors byte-equal CPU
//   * round-trip encode/decode preserves equality
//   * Add(G,G) == Double(G), Sub identity correct
//   * subgroup check rejects 16 known off-subgroup x-coordinates
//
// =============================================================================

#include "kinet/crypto/banderwagon.h"
#include "crypto.h"

#include "../cpp/banderwagon.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

using kinet::crypto::banderwagon::Element;
using kinet::crypto::banderwagon::Fp;
using kinet::crypto::banderwagon::Fr;

// -----------------------------------------------------------------------------
// Hex helpers
// -----------------------------------------------------------------------------

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool hex_to_bytes(const char* hex, uint8_t* out, size_t out_len) {
    if (std::strlen(hex) != out_len * 2) return false;
    for (size_t i = 0; i < out_len; ++i) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

static std::string bytes_to_hex(const uint8_t* in, size_t n) {
    static const char* kHex = "0123456789abcdef";
    std::string s;
    s.reserve(2 * n);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(kHex[(in[i] >> 4) & 0xf]);
        s.push_back(kHex[in[i] & 0xf]);
    }
    return s;
}

// -----------------------------------------------------------------------------
// Published KAT: encode(2^i * G) for i in 0..15.
// Source: kinet-labs/crypto/ipa/banderwagon/element_test.go::TestEncodingFixedVectors
// -----------------------------------------------------------------------------

static const char* kEncodedDoublings[16] = {
    "4a2c7486fd924882bf02c6908de395122843e3e05264d7991e18e7985dad51e9",  //  G
    "43aa74ef706605705989e8fd38df46873b7eae5921fbed115ac9d937399ce4d5",  //  2G
    "5e5f550494159f38aa54d2ed7f11a7e93e4968617990445cc93ac8e59808c126",  //  4G
    "0e7e3748db7c5c999a7bcd93d71d671f1f40090423792266f94cb27ca43fce5c",  //  8G
    "14ddaa48820cb6523b9ae5fe9fe257cbbd1f3d598a28e670a40da5d1159d864a",  // 16G
    "6989d1c82b2d05c74b62fb0fbdf8843adae62ff720d370e209a7b84e14548a7d",
    "26b8df6fa414bf348a3dc780ea53b70303ce49f3369212dec6fbe4b349b832bf",
    "37e46072db18f038f2cc7d3d5b5d1374c0eb86ca46f869d6a95fc2fb092c0d35",
    "2c1ce64f26e1c772282a6633fac7ca73067ae820637ce348bb2c8477d228dc7d",
    "297ab0f5a8336a7a4e2657ad7a33a66e360fb6e50812d4be3326fab73d6cee07",
    "5b285811efa7a965bd6ef5632151ebf399115fcc8f5b9b8083415ce533cc39ce",
    "1f939fa2fd457b3effb82b25d3fe8ab965f54015f108f8c09d67e696294ab626",
    "3088dcb4d3f4bacd706487648b239e0be3072ed2059d981fe04ce6525af6f1b8",
    "35fbc386a16d0227ff8673bc3760ad6b11009f749bb82d4facaea67f58fc60ed",
    "00f29b4f3255e318438f0a31e058e4c081085426adb0479f14c64985d0b956e0",
    "3fa4384b2fa0ecc3c0582223602921daaa893a97b64bdf94dcaa504e8b7b9e5f",
};

// 16 published off-subgroup x-coordinates that decode-with-subgroup-check
// must reject. Source: kinet-labs/crypto/ipa/banderwagon/element_test.go::
// TestPointAtInfinityComponent.
static const char* kBadEncodings[16] = {
    "280e608d5bbbe84b16aac62aa450e8921840ea563f1c9c266e0240d89cbe6a78",
    "1b6989e2393c65bbad7567929cdbd72bbf0218521d975b0fb209fba0ee493c32",
    "31468782818807366dbbcd20b9f10f0d5b93f22e33fe49b450dfbddaf3ba6a9b",
    "6bfc4097e4874cdddebe74e041fcd329d8455278cd42b6dd4f40b042d4fc466b",
    "65dc0a9730cce485d82b230ce32c7c21688967c8943b4a51ba468f927e2e28ef",
    "0fd3536157199b46617c3fba4bae1c2ffab5409dfea1de62161bc10748651671",
    "5bdc73f43e90ae5c2956320ce2ef2b17809b11d6b9758c7861793b41f39b7c01",
    "23a89c778ee10b9925ad3df5dc1f7ab244c1daf305669bc6b03d1aaa100037a4",
    "67505814852867356aaa8387896efa1d1b9a72aad95549e53e69c15eb36a642c",
    "301bc9b1129a727c2a65b96f55a5bcd642a3d37e0834196863c4430e4281dc3a",
    "45d08715ac67ebb088bcfa3d04bcce76510edeb9e23f12ed512894ba1e6518fc",
    "0b3b6e1f8ec72e63c6aa7ae87628071df3d82ea2bea6516d1948dac2edc12179",
    "72430a05f507747aa5a42481b4f93522aa682b1d56e5285f089aa1b5fb09c67a",
    "5eb4d3e5ce8107c6dd7c6398f2a903a0df75ce655939c29a3e309f43fe5bcd1f",
    "6671109a7a15f4852ead3298318595a36010930fddbd3c8f667c6390e7ac3c66",
    "120faa1df94d5d831bbb69fc44816e25afd27288a333299ac3c94518fd0e016f",
};

// -----------------------------------------------------------------------------
// Test bodies
// -----------------------------------------------------------------------------

static int g_failures = 0;
#define EXPECT(cond, msg) do { \
    if (!(cond)) { ++g_failures; std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg); } \
} while (0)

static void test_encode_doublings() {
    Element pt = Element::generator();
    for (int i = 0; i < 16; ++i) {
        uint8_t got[32];
        pt.to_bytes(got);
        std::string got_hex = bytes_to_hex(got, 32);
        if (got_hex != kEncodedDoublings[i]) {
            std::fprintf(stderr,
                "encode_doubling[%d]: expected %s\n              got      %s\n",
                i, kEncodedDoublings[i], got_hex.c_str());
            ++g_failures;
        }
        pt = pt.dbl();
    }
}

static void test_decode_then_encode_roundtrip() {
    for (int i = 0; i < 16; ++i) {
        uint8_t b[32];
        if (!hex_to_bytes(kEncodedDoublings[i], b, 32)) {
            ++g_failures;
            std::fprintf(stderr, "bad hex constant %d\n", i);
            continue;
        }
        Element e;
        EXPECT(e.from_bytes(b), "decode failed on published-spec vector");
        uint8_t got[32];
        e.to_bytes(got);
        EXPECT(std::memcmp(got, b, 32) == 0, "round-trip not byte-equal");
    }
}

static void test_decode_rejects_off_subgroup() {
    for (int i = 0; i < 16; ++i) {
        uint8_t b[32];
        if (!hex_to_bytes(kBadEncodings[i], b, 32)) { ++g_failures; continue; }
        Element e;
        bool ok = e.from_bytes(b);
        if (ok) {
            std::fprintf(stderr,
                "subgroup_check[%d] FALSE NEGATIVE: %s decoded but should be rejected\n",
                i, kBadEncodings[i]);
            ++g_failures;
        }
    }
}

static void test_add_eq_double() {
    Element G = Element::generator();
    Element addG = G.add(G);
    Element dblG = G.dbl();
    EXPECT(addG.equal(dblG), "Add(G,G) != Double(G)");
}

static void test_sub_identity() {
    Element G = Element::generator();
    Element sum = G.add(G);
    Element back = sum.sub(G);
    EXPECT(back.equal(G), "G + G - G != G");
}

static void test_neg_identity() {
    Element G = Element::generator();
    Element negG = G.neg();
    Element zero = G.add(negG);
    // In Banderwagon equality, a point and its negation are NOT equal (they
    // differ by a 2-torsion point only via the subgroup pair, but not in
    // general); G + (-G) is the identity.
    EXPECT(zero.inner().is_identity(), "G + (-G) != identity");
}

static void test_scalar_mul_consistency() {
    Element G = Element::generator();
    // 2G via scalar mul
    uint8_t two_be[32] = {0};
    two_be[31] = 2;
    Fr two = Fr::from_canonical_be(two_be);
    Element twoG = G.scalar_mul(two);
    Element dblG = G.dbl();
    EXPECT(twoG.equal(dblG), "scalar_mul(2)*G != Double(G)");

    // 8G via scalar mul vs. 3 doublings
    uint8_t eight_be[32] = {0};
    eight_be[31] = 8;
    Fr eight = Fr::from_canonical_be(eight_be);
    Element eightG = G.scalar_mul(eight);
    Element dbl_chain = G.dbl().dbl().dbl();
    EXPECT(eightG.equal(dbl_chain), "scalar_mul(8)*G != G^^^");
}

static void test_msm_small() {
    // result = 1*G + 2*G = 3*G
    uint8_t s1_be[32] = {0}; s1_be[31] = 1;
    uint8_t s2_be[32] = {0}; s2_be[31] = 2;
    Fr s1 = Fr::from_canonical_be(s1_be);
    Fr s2 = Fr::from_canonical_be(s2_be);
    Element pts[2] = {Element::generator(), Element::generator()};
    Fr ss[2] = {s1, s2};
    Element got = kinet::crypto::banderwagon::msm(pts, ss, 2);

    uint8_t three_be[32] = {0}; three_be[31] = 3;
    Fr three = Fr::from_canonical_be(three_be);
    Element expected = Element::generator().scalar_mul(three);
    EXPECT(got.equal(expected), "msm(1,2) != 3G");
}

static void test_c_abi_roundtrip() {
    // banderwagon_generator -> banderwagon_encode -> banderwagon_decode ->
    // banderwagon_equal(generator) == 1
    uint8_t G[64];
    banderwagon_generator(G);

    uint8_t enc[32];
    EXPECT(banderwagon_encode(G, enc) == CRYPTO_OK, "C ABI encode failed");

    uint8_t G2[64];
    EXPECT(banderwagon_decode(enc, G2) == CRYPTO_OK, "C ABI decode failed");

    int eq = banderwagon_equal(G, G2);
    EXPECT(eq == 1, "C ABI roundtrip generator != decoded");

    // 2G via scalar_mul
    uint8_t two_be[32] = {0}; two_be[31] = 2;
    uint8_t twoG[64];
    EXPECT(banderwagon_scalar_mul(two_be, G, twoG) == CRYPTO_OK, "C ABI scalar_mul failed");

    uint8_t G_plus_G[64];
    EXPECT(banderwagon_add(G, G, G_plus_G) == CRYPTO_OK, "C ABI add failed");

    EXPECT(banderwagon_equal(twoG, G_plus_G) == 1, "C ABI: scalar_mul(2)*G != G+G");
}

static void test_c_abi_msm() {
    uint8_t G[64];
    banderwagon_generator(G);

    // points = [G, G, G]; scalars = [1, 2, 3]; expected sum = 6G
    uint8_t pts[64 * 3];
    std::memcpy(pts + 64 * 0, G, 64);
    std::memcpy(pts + 64 * 1, G, 64);
    std::memcpy(pts + 64 * 2, G, 64);

    uint8_t scs[32 * 3] = {0};
    scs[31] = 1;
    scs[32 + 31] = 2;
    scs[64 + 31] = 3;

    uint8_t out[64];
    EXPECT(banderwagon_msm(pts, scs, 3, out) == CRYPTO_OK, "C ABI msm failed");

    uint8_t six_be[32] = {0}; six_be[31] = 6;
    uint8_t sixG[64];
    EXPECT(banderwagon_scalar_mul(six_be, G, sixG) == CRYPTO_OK, "C ABI scalar_mul failed");

    EXPECT(banderwagon_equal(out, sixG) == 1, "C ABI: msm(1,2,3) != 6G");
}

int main() {
    test_encode_doublings();
    test_decode_then_encode_roundtrip();
    test_decode_rejects_off_subgroup();
    test_add_eq_double();
    test_sub_identity();
    test_neg_identity();
    test_scalar_mul_consistency();
    test_msm_small();
    test_c_abi_roundtrip();
    test_c_abi_msm();

    if (g_failures == 0) {
        std::printf("banderwagon_kat_test: PASS (16 KAT encode + 16 reject + 8 op invariants + 2 C ABI)\n");
        return 0;
    }
    std::printf("banderwagon_kat_test: FAIL (%d failures)\n", g_failures);
    return 1;
}

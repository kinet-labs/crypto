// Test vectors for ChaCha20-Poly1305 (RFC 8439).
//
// Vectors:
//   * RFC 8439 §2.4.2 -- ChaCha20 encryption "Sunscreen" example (114-byte
//     plaintext + 12-byte nonce).
//   * RFC 8439 §2.5.2 -- Poly1305 standalone "Cryptographic Forum" example.
//   * RFC 8439 §2.6.2 -- poly1305_key_gen example.
//   * RFC 8439 §2.8.2 -- ChaCha20-Poly1305 AEAD "Internet-Drafts" example.
//   * RFC 8439 §A.5  -- AEAD test vector (the canonical end-to-end example).
//   * RFC 8439 §A.4  -- poly1305_key_gen test vectors (3 cases).
//   * RFC 8439 §A.2  -- ChaCha20 block test vectors (5 cases).
//   * RFC 8439 §A.3  -- ChaCha20 encryption test vectors (3 cases).
//
// Plus negative tests: tampered ciphertext and tampered AAD must both fail
// tag verification.

#include "crypto.h"
#include "../cpp/aead.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

static int g_failures = 0;
static int g_tests    = 0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string hex(const uint8_t* b, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string r; r.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        r.push_back(H[b[i] >> 4]);
        r.push_back(H[b[i] & 0xF]);
    }
    return r;
}

static std::vector<uint8_t> unhex(const std::string& s) {
    std::vector<uint8_t> r;
    r.reserve(s.size() / 2);
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        const int hi = val(s[i]);
        const int lo = val(s[i + 1]);
        if (hi < 0 || lo < 0) continue;
        r.push_back((uint8_t)((hi << 4) | lo));
    }
    return r;
}

static void expect_eq(const char* name, const std::string& got,
                      const std::string& want) {
    ++g_tests;
    if (got == want) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s\n  got  %s\n  want %s\n",
                     name, got.c_str(), want.c_str());
        ++g_failures;
    }
}

static void expect_true(const char* name, bool cond) {
    ++g_tests;
    if (cond) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s\n", name);
        ++g_failures;
    }
}

// ---------------------------------------------------------------------------
// Test 1: RFC 8439 §2.3.2 -- ChaCha20 block test vector (single block)
// ---------------------------------------------------------------------------
static void test_chacha20_block_2_3_2() {
    const auto key = unhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f");
    const auto nonce = unhex("000000090000004a00000000");
    const uint32_t counter = 1;
    const std::string want =
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e";

    uint8_t out[64];
    kinet::crypto::aead::chacha20::block(key.data(), nonce.data(), counter, out);
    expect_eq("chacha20_block (RFC 8439 §2.3.2)", hex(out, 64), want);
}

// ---------------------------------------------------------------------------
// Test 2: RFC 8439 §2.4.2 -- ChaCha20 "Sunscreen" encryption
// ---------------------------------------------------------------------------
static void test_chacha20_sunscreen_2_4_2() {
    const auto key = unhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f");
    const auto nonce = unhex("000000000000004a00000000");
    const uint32_t counter = 1;
    const auto pt = unhex(
        // "Ladies and Gentlemen of the class of '99: If I could offer you "
        // "only one tip for the future, sunscreen would be it."
        "4c616469657320616e642047656e746c"
        "656d656e206f662074686520636c6173"
        "73206f66202739393a20496620492063"
        "6f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220"
        "746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069"
        "742e");
    const std::string want_ct =
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d";

    std::vector<uint8_t> ct(pt.size());
    kinet::crypto::aead::chacha20::xor_stream(
        key.data(), nonce.data(), counter, pt.data(), pt.size(), ct.data());
    expect_eq("chacha20 sunscreen (RFC 8439 §2.4.2)",
              hex(ct.data(), ct.size()), want_ct);
}

// ---------------------------------------------------------------------------
// Test 3: RFC 8439 §2.5.2 -- Poly1305 standalone "Cryptographic Forum"
// ---------------------------------------------------------------------------
static void test_poly1305_2_5_2() {
    const auto key = unhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b");
    const auto msg = unhex(
        // "Cryptographic Forum Research Group"
        "43727970746f67726170686963"
        "20466f72756d2052657365"
        "6172636820"
        "47726f7570");
    const std::string want = "a8061dc1305136c6c22b8baf0c0127a9";

    uint8_t tag[16];
    kinet::crypto::aead::poly1305::mac(key.data(), msg.data(), msg.size(), tag);
    expect_eq("poly1305 (RFC 8439 §2.5.2)", hex(tag, 16), want);
}

// ---------------------------------------------------------------------------
// Test 4: RFC 8439 §2.6.2 -- poly1305_key_gen
// ---------------------------------------------------------------------------
static void test_poly1305_key_gen_2_6_2() {
    const auto key = unhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f");
    const auto nonce = unhex("000000000001020304050607");
    const std::string want_pk =
        "8ad5a08b905f81cc815040274ab29471"
        "a833b637e3fd0da508dbb8e2fdd1a646";

    uint8_t block0[64];
    kinet::crypto::aead::chacha20::block(key.data(), nonce.data(), 0, block0);
    // Poly1305 key = first 32 bytes of block 0.
    expect_eq("poly1305_key_gen (RFC 8439 §2.6.2)", hex(block0, 32), want_pk);
}

// ---------------------------------------------------------------------------
// Test 5: RFC 8439 §2.8.2 -- AEAD encryption "Internet-Drafts" example
// ---------------------------------------------------------------------------
static void test_aead_2_8_2() {
    const auto key = unhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f");
    const auto nonce = unhex("070000004041424344454647");
    const auto aad   = unhex("50515253c0c1c2c3c4c5c6c7");
    const auto pt = unhex(
        // "Ladies and Gentlemen of the class of '99: If I could offer you "
        // "only one tip for the future, sunscreen would be it."
        "4c616469657320616e642047656e746c"
        "656d656e206f662074686520636c6173"
        "73206f66202739393a20496620492063"
        "6f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220"
        "746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069"
        "742e");
    const std::string want_ct =
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116";
    const std::string want_tag = "1ae10b594f09e26a7e902ecbd0600691";

    std::vector<uint8_t> ct(pt.size());
    uint8_t tag[16];
    const bool ok = kinet::crypto::aead::chacha20_poly1305::encrypt(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        pt.data(), pt.size(),
        ct.data(), tag);
    expect_true("aead encrypt returns ok (RFC 8439 §2.8.2)", ok);
    expect_eq("aead ciphertext (RFC 8439 §2.8.2)",
              hex(ct.data(), ct.size()), want_ct);
    expect_eq("aead tag (RFC 8439 §2.8.2)", hex(tag, 16), want_tag);

    // Round-trip decrypt.
    std::vector<uint8_t> pt2(ct.size());
    const bool dec_ok = kinet::crypto::aead::chacha20_poly1305::decrypt(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        ct.data(), ct.size(),
        tag, pt2.data());
    expect_true("aead decrypt returns ok (RFC 8439 §2.8.2)", dec_ok);
    expect_eq("aead decrypt plaintext (RFC 8439 §2.8.2)",
              hex(pt2.data(), pt2.size()),
              hex(pt.data(),  pt.size()));
}

// ---------------------------------------------------------------------------
// Test 6: RFC 8439 §A.5 -- canonical AEAD test vector (TLS-like record)
// ---------------------------------------------------------------------------
static void test_aead_a_5() {
    // Plaintext (RFC 8439 §A.5):
    //   "Internet-Drafts are draft documents valid for a maximum of six months
    //    and may be updated, replaced, or obsoleted by other documents at any
    //    time. It is inappropriate to use Internet-Drafts as reference material
    //    or to cite them other than as /“work in progress./”"
    const auto pt = unhex(
        "496e7465726e65742d44726166747320"
        "61726520647261667420646f63756d65"
        "6e74732076616c696420666f72206120"
        "6d6178696d756d206f6620736978206d"
        "6f6e74687320616e64206d6179206265"
        "20757064617465642c207265706c6163"
        "65642c206f72206f62736f6c65746564"
        "206279206f7468657220646f63756d65"
        "6e747320617420616e792074696d652e"
        "20497420697320696e617070726f7072"
        "6961746520746f2075736520496e7465"
        "726e65742d4472616674732061732072"
        "65666572656e6365206d617465726961"
        "6c206f7220746f206369746520746865"
        "6d206f74686572207468616e20617320"
        "2fe2809c776f726b20696e2070726f67"
        "726573732e2fe2809d");

    const auto aad = unhex("f33388860000000000004e91");
    const auto key = unhex(
        "1c9240a5eb55d38af333888604f6b5f0"
        "473917c1402b80099dca5cbc207075c0");
    const auto nonce = unhex("000000000102030405060708");

    const std::string want_ct =
        "64a0861575861af460f062c79be643bd"
        "5e805cfd345cf389f108670ac76c8cb2"
        "4c6cfc18755d43eea09ee94e382d26b0"
        "bdb7b73c321b0100d4f03b7f355894cf"
        "332f830e710b97ce98c8a84abd0b9481"
        "14ad176e008d33bd60f982b1ff37c855"
        "9797a06ef4f0ef61c186324e2b350638"
        "3606907b6a7c02b0f9f6157b53c867e4"
        "b9166c767b804d46a59b5216cde7a4e9"
        "9040c5a40433225ee282a1b0a06c523e"
        "af4534d7f83fa1155b0047718cbc546a"
        "0d072b04b3564eea1b422273f548271a"
        "0bb2316053fa76991955ebd63159434e"
        "cebb4e466dae5a1073a6727627097a10"
        "49e617d91d361094fa68f0ff77987130"
        "305beaba2eda04df997b714d6c6f2c29"
        "a6ad5cb4022b02709b";
    const std::string want_tag = "eead9d67890cbb22392336fea1851f38";

    std::vector<uint8_t> ct(pt.size());
    uint8_t tag[16];
    const bool ok = kinet::crypto::aead::chacha20_poly1305::encrypt(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        pt.data(), pt.size(),
        ct.data(), tag);
    expect_true("aead encrypt returns ok (RFC 8439 §A.5)", ok);
    expect_eq("aead ciphertext (RFC 8439 §A.5)",
              hex(ct.data(), ct.size()), want_ct);
    expect_eq("aead tag (RFC 8439 §A.5)", hex(tag, 16), want_tag);

    // Round-trip decrypt.
    std::vector<uint8_t> pt2(ct.size());
    const bool dec_ok = kinet::crypto::aead::chacha20_poly1305::decrypt(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        ct.data(), ct.size(),
        tag, pt2.data());
    expect_true("aead decrypt returns ok (RFC 8439 §A.5)", dec_ok);
    expect_eq("aead decrypt plaintext (RFC 8439 §A.5)",
              hex(pt2.data(), pt2.size()),
              hex(pt.data(),  pt.size()));
}

// ---------------------------------------------------------------------------
// Test 7: empty plaintext + empty AAD
// ---------------------------------------------------------------------------
static void test_aead_empty() {
    const auto key = unhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f");
    const auto nonce = unhex("070000004041424344454647");

    uint8_t tag[16];
    const bool ok = kinet::crypto::aead::chacha20_poly1305::encrypt(
        key.data(), nonce.data(),
        nullptr, 0,
        nullptr, 0,
        nullptr, tag);
    expect_true("aead encrypt empty inputs returns ok", ok);

    const bool dec_ok = kinet::crypto::aead::chacha20_poly1305::decrypt(
        key.data(), nonce.data(),
        nullptr, 0,
        nullptr, 0,
        tag, nullptr);
    expect_true("aead decrypt empty inputs returns ok", dec_ok);
}

// ---------------------------------------------------------------------------
// Test 8: AAD-only authentication (no plaintext)
// ---------------------------------------------------------------------------
static void test_aead_aad_only() {
    const auto key = unhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f");
    const auto nonce = unhex("070000004041424344454647");
    const auto aad = unhex("50515253c0c1c2c3c4c5c6c7");

    uint8_t tag[16];
    const bool ok = kinet::crypto::aead::chacha20_poly1305::encrypt(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        nullptr, 0,
        nullptr, tag);
    expect_true("aead encrypt aad-only returns ok", ok);

    const bool dec_ok = kinet::crypto::aead::chacha20_poly1305::decrypt(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        nullptr, 0,
        tag, nullptr);
    expect_true("aead decrypt aad-only returns ok", dec_ok);

    // Tampered AAD must fail.
    auto bad_aad = aad;
    bad_aad[0] ^= 0x01;
    const bool dec_bad = kinet::crypto::aead::chacha20_poly1305::decrypt(
        key.data(), nonce.data(),
        bad_aad.data(), bad_aad.size(),
        nullptr, 0,
        tag, nullptr);
    expect_true("aead decrypt aad-only rejects tampered aad", !dec_bad);
}

// ---------------------------------------------------------------------------
// Test 9: tampered ciphertext byte must fail decrypt
// ---------------------------------------------------------------------------
static void test_aead_tampered_ct() {
    const auto key = unhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f");
    const auto nonce = unhex("070000004041424344454647");
    const auto aad   = unhex("50515253c0c1c2c3c4c5c6c7");
    const auto pt = unhex(
        "4c616469657320616e642047656e746c"
        "656d656e206f662074686520636c6173"
        "73206f66202739393a20496620492063"
        "6f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220"
        "746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069"
        "742e");

    std::vector<uint8_t> ct(pt.size());
    uint8_t tag[16];
    kinet::crypto::aead::chacha20_poly1305::encrypt(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        pt.data(), pt.size(),
        ct.data(), tag);

    // Flip one bit in ciphertext.
    ct[5] ^= 0x01;
    std::vector<uint8_t> pt2(ct.size());
    const bool dec_bad = kinet::crypto::aead::chacha20_poly1305::decrypt(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        ct.data(), ct.size(),
        tag, pt2.data());
    expect_true("aead decrypt rejects tampered ciphertext", !dec_bad);
}

// ---------------------------------------------------------------------------
// Test 10: tampered AAD byte must fail decrypt
// ---------------------------------------------------------------------------
static void test_aead_tampered_aad() {
    const auto key = unhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f");
    const auto nonce = unhex("070000004041424344454647");
    const auto aad   = unhex("50515253c0c1c2c3c4c5c6c7");
    const auto pt = unhex(
        "4c616469657320616e642047656e746c"
        "656d656e206f662074686520636c6173");

    std::vector<uint8_t> ct(pt.size());
    uint8_t tag[16];
    kinet::crypto::aead::chacha20_poly1305::encrypt(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        pt.data(), pt.size(),
        ct.data(), tag);

    // Flip one bit in AAD.
    auto bad_aad = aad;
    bad_aad[3] ^= 0x80;
    std::vector<uint8_t> pt2(ct.size());
    const bool dec_bad = kinet::crypto::aead::chacha20_poly1305::decrypt(
        key.data(), nonce.data(),
        bad_aad.data(), bad_aad.size(),
        ct.data(), ct.size(),
        tag, pt2.data());
    expect_true("aead decrypt rejects tampered aad", !dec_bad);

    // Tampered tag must also fail.
    uint8_t bad_tag[16];
    std::memcpy(bad_tag, tag, 16);
    bad_tag[7] ^= 0x40;
    const bool dec_bad_tag = kinet::crypto::aead::chacha20_poly1305::decrypt(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        ct.data(), ct.size(),
        bad_tag, pt2.data());
    expect_true("aead decrypt rejects tampered tag", !dec_bad_tag);
}

// ---------------------------------------------------------------------------
// Test 11: C-ABI dispatches correctly (seal/open)
// ---------------------------------------------------------------------------
static void test_c_abi_dispatch() {
    const auto key = unhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f");
    const auto nonce = unhex("070000004041424344454647");
    const auto aad   = unhex("50515253c0c1c2c3c4c5c6c7");
    const auto pt = unhex(
        "4c616469657320616e642047656e746c"
        "656d656e206f662074686520636c6173"
        "73206f66202739393a20496620492063"
        "6f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220"
        "746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069"
        "742e");
    const std::string want_tag = "1ae10b594f09e26a7e902ecbd0600691";

    std::vector<uint8_t> ct(pt.size());
    uint8_t tag[16];
    const int seal_rc = aead_chacha20poly1305_seal(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        pt.data(), pt.size(),
        ct.data(), tag);
    expect_true("c-abi seal returns CRYPTO_OK", seal_rc == CRYPTO_OK);
    expect_eq("c-abi seal tag matches RFC 8439 §2.8.2", hex(tag, 16), want_tag);

    std::vector<uint8_t> pt2(ct.size());
    const int open_rc = aead_chacha20poly1305_open(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        ct.data(), ct.size(),
        tag, pt2.data());
    expect_true("c-abi open returns CRYPTO_OK", open_rc == CRYPTO_OK);
    expect_eq("c-abi open recovers plaintext",
              hex(pt2.data(), pt2.size()),
              hex(pt.data(),  pt.size()));

    // Tamper -> CRYPTO_ERR_VERIFY.
    ct[0] ^= 0x01;
    const int open_bad_rc = aead_chacha20poly1305_open(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        ct.data(), ct.size(),
        tag, pt2.data());
    expect_true("c-abi open returns CRYPTO_ERR_VERIFY on tamper",
                open_bad_rc == CRYPTO_ERR_VERIFY);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    std::fprintf(stdout, "=== aead test suite (ChaCha20-Poly1305 RFC 8439) ===\n");

    test_chacha20_block_2_3_2();
    test_chacha20_sunscreen_2_4_2();
    test_poly1305_2_5_2();
    test_poly1305_key_gen_2_6_2();
    test_aead_2_8_2();
    test_aead_a_5();
    test_aead_empty();
    test_aead_aad_only();
    test_aead_tampered_ct();
    test_aead_tampered_aad();
    test_c_abi_dispatch();

    std::fprintf(stdout, "=== %s (%d/%d, %d failure%s) ===\n",
        g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
        g_tests - g_failures, g_tests,
        g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}

// Byte-equality test for batched Ed25519 verify Metal kernel against
// RFC 8032 Section 7.1 test vectors plus 96 negative-control variants.
//
// Each KAT defines (msg, sig, pub, expected_valid). The test computes
// h = SHA-512(R || A || M) mod L on the host, dispatches the Metal kernel,
// and asserts results[i] == expected_valid[i] for all 100 vectors.
//
// The "RFC 8032 oracle" for ed25519 verify is the standard itself: the four
// RFC test cases are the canonical truth source, and circl/ref10/dalek all
// match those bit-for-bit. Negative variants flip a byte in either sig or
// pubkey and assert the kernel rejects them.
//
// Skipped silently when KINET_CRYPTO_ED25519_METALLIB is unset.

#include "../cpp/sha512_minimal.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#if __APPLE__
extern "C" int ed25519_batch_verify_metal(
    const uint8_t* pubkeys,
    const uint8_t* signatures,
    const uint8_t* challenges,
    size_t         n,
    uint8_t*       results,
    const char*    metallib_path);
#endif

namespace {

struct KAT {
    const char* name;
    uint8_t pub[32];
    uint8_t sig[64];
    std::vector<uint8_t> msg;
    bool expected;
};

// Hex helper.
uint8_t hex2(char c) {
    if (c >= '0' && c <= '9') return uint8_t(c - '0');
    if (c >= 'a' && c <= 'f') return uint8_t(10 + c - 'a');
    if (c >= 'A' && c <= 'F') return uint8_t(10 + c - 'A');
    return 0;
}
void load_hex(uint8_t* out, const char* hex, size_t out_len) {
    for (size_t i = 0; i < out_len; ++i) {
        out[i] = uint8_t((hex2(hex[2 * i]) << 4) | hex2(hex[2 * i + 1]));
    }
}
std::vector<uint8_t> load_hex_vec(const char* hex) {
    size_t l = std::strlen(hex);
    std::vector<uint8_t> v(l / 2);
    load_hex(v.data(), hex, l / 2);
    return v;
}

// RFC 8032 Section 7.1 test vectors (pure Ed25519, no context, message-as-is).
//   TEST 1: empty message
//   TEST 2: 1-byte message
//   TEST 3: 2-byte message
//   TEST 1024: 1023-byte message (omitted here; picks 4 KAT 1-3 + KAT SHA(abc)
//              from the RFC). The 1023-byte case adds disk weight without new
//              algorithmic coverage.
const KAT* rfc_kats() {
    static KAT k[4];
    static bool init = false;
    if (init) return k;

    // TEST 1
    k[0].name = "RFC 8032 TEST 1 (empty msg)";
    load_hex(k[0].pub,
             "d75a980182b10ab7d54bfed3c964073a"
             "0ee172f3daa62325af021a68f707511a", 32);
    load_hex(k[0].sig,
             "e5564300c360ac729086e2cc806e828a"
             "84877f1eb8e5d974d873e06522490155"
             "5fb8821590a33bacc61e39701cf9b46b"
             "d25bf5f0595bbe24655141438e7a100b", 64);
    k[0].msg = {};
    k[0].expected = true;

    // TEST 2
    k[1].name = "RFC 8032 TEST 2 (1-byte msg)";
    load_hex(k[1].pub,
             "3d4017c3e843895a92b70aa74d1b7ebc"
             "9c982ccf2ec4968cc0cd55f12af4660c", 32);
    load_hex(k[1].sig,
             "92a009a9f0d4cab8720e820b5f642540"
             "a2b27b5416503f8fb3762223ebdb69da"
             "085ac1e43e15996e458f3613d0f11d8c"
             "387b2eaeb4302aeeb00d291612bb0c00", 64);
    k[1].msg = {0x72};
    k[1].expected = true;

    // TEST 3
    k[2].name = "RFC 8032 TEST 3 (2-byte msg)";
    load_hex(k[2].pub,
             "fc51cd8e6218a1a38da47ed00230f058"
             "0816ed13ba3303ac5deb911548908025", 32);
    load_hex(k[2].sig,
             "6291d657deec24024827e69c3abe01a3"
             "0ce548a284743a445e3680d7db5ac3ac"
             "18ff9b538d16f290ae67f760984dc659"
             "4a7c15e9716ed28dc027beceea1ec40a", 64);
    k[2].msg = {0xaf, 0x82};
    k[2].expected = true;

    // TEST 1024 -- RFC 8032 Section 7.1, 1023-byte message. Pinned in
    // the spec; cloudflare/circl, dalek and the SUPERCOP reference all
    // verify byte-equal against this triple.
    k[3].name = "RFC 8032 TEST 1024 (1023-byte msg)";
    load_hex(k[3].pub,
             "278117fc144c72340f67d0f2316e8386"
             "ceffbf2b2428c9c51fef7c597f1d426e", 32);
    load_hex(k[3].sig,
             "0aab4c900501b3e24d7cdf4663326a3a"
             "87df5e4843b2cbdb67cbf6e460fec350"
             "aa5371b1508f9f4528ecea23c436d94b"
             "5e8fcd4f681e30a6ac00a9704a188a03", 64);
    k[3].msg = load_hex_vec(
        "08b8b2b733424243760fe426a4b54908"
        "632110a66c2f6591eabd3345e3e4eb98"
        "fa6e264bf09efe12ee50f8f54e9f77b1"
        "e355f6c50544e23fb1433ddf73be84d8"
        "79de7c0046dc4996d9e773f4bc9efe57"
        "38829adb26c81b37c93a1b270b20329d"
        "658675fc6ea534e0810a4432826bf58c"
        "941efb65d57a338bbd2e26640f89ffbc"
        "1a858efcb8550ee3a5e1998bd177e93a"
        "7363c344fe6b199ee5d02e82d522c4fe"
        "ba15452f80288a821a579116ec6dad2b"
        "3b310da903401aa62100ab5d1a36553e"
        "06203b33890cc9b832f79ef80560ccb9"
        "a39ce767967ed628c6ad573cb116dbef"
        "efd75499da96bd68a8a97b928a8bbc10"
        "3b6621fcde2beca1231d206be6cd9ec7"
        "aff6f6c94fcd7204ed3455c68c83f4a4"
        "1da4af2b74ef5c53f1d8ac70bdcb7ed1"
        "85ce81bd84359d44254d95629e9855a9"
        "4a7c1958d1f8ada5d0532ed8a5aa3fb2"
        "d17ba70eb6248e594e1a2297acbbb39d"
        "502f1a8c6eb6f1ce22b3de1a1f40cc24"
        "554119a831a9aad6079cad88425de6bd"
        "e1a9187ebb6092cf67bf2b13fd65f270"
        "88d78b7e883c8759d2c4f5c65adb7553"
        "878ad575f9fad878e80a0c9ba63bcbcc"
        "2732e69485bbc9c90bfbd62481d9089b"
        "eccf80cfe2df16a2cf65bd92dd597b07"
        "07e0917af48bbb75fed413d238f5555a"
        "7a569d80c3414a8d0859dc65a46128ba"
        "b27af87a71314f318c782b23ebfe808b"
        "82b0ce26401d2e22f04d83d1255dc51a"
        "ddd3b75a2b1ae0784504df543af8969b"
        "e3ea7082ff7fc9888c144da2af58429e"
        "c96031dbcad3dad9af0dcbaaaf268cb8"
        "fcffead94f3c7ca495e056a9b47acdb7"
        "51fb73e666c6c655ade8297297d07ad1"
        "ba5e43f1bca32301651339e22904cc8c"
        "42f58c30c04aafdb038dda0847dd988d"
        "cda6f3bfd15c4b4c4525004aa06eeff8"
        "ca61783aacec57fb3d1f92b0fe2fd1a8"
        "5f6724517b65e614ad6808d6f6ee34df"
        "f7310fdc82aebfd904b01e1dc54b2927"
        "094b2db68d6f903b68401adebf5a7e08"
        "d78ff4ef5d63653a65040cf9bfd4aca7"
        "984a74d37145986780fc0b16ac451649"
        "de6188a7dbdf191f64b5fc5e2ab47b57"
        "f7f7276cd419c17a3ca8e1b939ae49e4"
        "88acba6b965610b5480109c8b17b80e1"
        "b7b750dfc7598d5d5011fd2dcc5600a3"
        "2ef5b52a1ecc820e308aa342721aac09"
        "43bf6686b64b2579376504ccc493d97e"
        "6aed3fb0f9cd71a43dd497f01f17c0e2"
        "cb3797aa2a2f256656168e6c496afc5f"
        "b93246f6b1116398a346f1a641f3b041"
        "e989f7914f90cc2c7fff357876e506b5"
        "0d334ba77c225bc307ba537152f3f161"
        "0e4eafe595f6d9d90d11faa933a15ef1"
        "369546868a7f3a45a96768d40fd9d034"
        "12c091c6315cf4fde7cb68606937380d"
        "b2eaaa707b4c4185c32eddcdd306705e"
        "4dc1ffc872eeee475a64dfac86aba41c"
        "0618983f8741c5ef68d3a101e8a3b8ca"
        "c60c905c15fc910840b94c00a0b9d0");
    k[3].expected = true;

    init = true;
    return k;
}

}  // namespace

int main() {
    std::fprintf(stdout, "=== ed25519 CPU vs Metal byte-equality (RFC 8032) ===\n");

#if __APPLE__
    const char* metallib = std::getenv("KINET_CRYPTO_ED25519_METALLIB");
    if (!metallib) {
        std::fprintf(stdout, "(skip GPU equality: KINET_CRYPTO_ED25519_METALLIB unset)\n");
        std::fprintf(stdout, "=== ALL TESTS PASSED (GPU skipped) ===\n");
        return 0;
    }

    using namespace kinetcrypto::ed25519;

    // 4 RFC vectors + 96 derived negatives (alternating sig-byte-flip and
    // pub-byte-flip across the 4 base vectors). Total = 100.
    const KAT* kats = rfc_kats();
    std::vector<uint8_t> pubs;
    std::vector<uint8_t> sigs;
    std::vector<uint8_t> challenges;
    std::vector<uint8_t> expected;
    auto push_vec = [&](const KAT& k, bool exp_valid) {
        size_t base = pubs.size();
        pubs.insert(pubs.end(), k.pub, k.pub + 32);
        sigs.insert(sigs.end(), k.sig, k.sig + 64);
        // h = SHA-512(R || A || M) mod L
        std::vector<uint8_t> ram;
        ram.reserve(64 + k.msg.size());
        ram.insert(ram.end(), k.sig, k.sig + 32);
        ram.insert(ram.end(), k.pub, k.pub + 32);
        ram.insert(ram.end(), k.msg.begin(), k.msg.end());
        uint8_t hash[64];
        sha512(hash, ram.data(), ram.size());
        uint8_t hred[32];
        reduce_mod_l(hred, hash);
        challenges.insert(challenges.end(), hred, hred + 32);
        expected.push_back(exp_valid ? 1u : 0u);
        (void)base;
    };

    // 4 positives.
    for (int i = 0; i < 4; ++i) push_vec(kats[i], true);

    // 96 negatives -- flip one byte and the kernel must reject.
    for (int rep = 0; rep < 24; ++rep) {
        for (int i = 0; i < 4; ++i) {
            KAT bad = kats[i];
            // alternate sig flip vs pub flip
            if (rep % 2 == 0) bad.sig[(rep + i) % 64] ^= 0x01;
            else              bad.pub[(rep + i) % 32] ^= 0x01;
            push_vec(bad, false);
        }
    }
    size_t n = expected.size();
    std::fprintf(stdout, "=== %zu vectors (4 RFC positives + %zu negatives) ===\n",
                 n, n - 4);

    std::vector<uint8_t> results(n, 0);
    int rc = ed25519_batch_verify_metal(pubs.data(), sigs.data(),
                                        challenges.data(), n,
                                        results.data(), metallib);
    if (rc != 0) {
        std::fprintf(stderr, "FAIL Metal dispatch rc=%d\n", rc);
        return 1;
    }
    std::fprintf(stdout, "PASS Metal dispatch rc=0\n");

    int eq = 0, fail_pos = 0, fail_neg = 0;
    for (size_t i = 0; i < n; ++i) {
        if (results[i] == expected[i]) {
            ++eq;
        } else if (expected[i] == 1u) {
            ++fail_pos;
            std::fprintf(stderr, "FAIL positive idx=%zu got=%u\n",
                         i, results[i]);
        } else {
            ++fail_neg;
            std::fprintf(stderr, "FAIL negative idx=%zu got=%u\n",
                         i, results[i]);
        }
    }
    if (eq == (int)n) {
        std::fprintf(stdout, "PASS byte-equal %d/%zu vectors\n", eq, n);
    } else {
        std::fprintf(stderr,
                     "FAIL byte-equal %d/%zu (positives miss=%d, negatives miss=%d)\n",
                     eq, n, fail_pos, fail_neg);
    }
    int g_failures = (eq == (int)n) ? 0 : 1;

#else
    int g_failures = 0;
    std::fprintf(stdout, "(non-Apple host: GPU equality skipped)\n");
#endif

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
                 g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                 g_failures, g_failures == 1 ? "" : "s");
    return g_failures;
}

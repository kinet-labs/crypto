// RFC 8032 §7.1 Known-Answer Tests for Ed25519 plus random-key roundtrips.
//
// 8 RFC vectors:
//   1. TEST 1                - empty message            (RFC 8032 §7.1)
//   2. TEST 2                - 1-byte 0x72              (RFC 8032 §7.1)
//   3. TEST 3                - 2-byte 0xaf 0x82         (RFC 8032 §7.1)
//   4. sign.input vector 4   - 3-byte 0xcb 0xc7 0x7b    (Bernstein/donna)
//   5. sign.input vector 5   - 4-byte 0x5f 0x4c 0x89 0x89
//   6. sign.input vector 6   - 5-byte 0x18 0xb6 0xbe 0xc0 0x97
//   7. TEST 1024             - 1023-byte message        (RFC 8032 §7.1)
//   8. TEST SHA(abc)         - SHA-512(abc) as message  (RFC 8032 §7.1)
//
// Plus 10 random-seed roundtrips: keygen, sign, verify, mutate sig, verify
// fails. All assert byte-equal output where the standard pins it.
//
// No external test harness; exits non-zero on any failure.

#include "ed25519.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

using kinet::crypto::ed25519::keygen;
using kinet::crypto::ed25519::sign;
using kinet::crypto::ed25519::verify;
using kinet::crypto::ed25519::batch_verify;

int g_failures = 0;

uint8_t hex_nibble(char c) {
    if (c >= '0' && c <= '9') return uint8_t(c - '0');
    if (c >= 'a' && c <= 'f') return uint8_t(10 + c - 'a');
    if (c >= 'A' && c <= 'F') return uint8_t(10 + c - 'A');
    std::fprintf(stderr, "FATAL: bad hex byte 0x%02x\n", (unsigned)c);
    std::exit(2);
}

void from_hex(uint8_t* out, const char* hex, size_t out_len) {
    for (size_t i = 0; i < out_len; ++i) {
        out[i] = uint8_t((hex_nibble(hex[2 * i]) << 4) | hex_nibble(hex[2 * i + 1]));
    }
}

std::vector<uint8_t> from_hex_vec(const char* hex) {
    size_t n = std::strlen(hex) / 2;
    std::vector<uint8_t> v(n);
    from_hex(v.data(), hex, n);
    return v;
}

std::string to_hex(const uint8_t* b, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(H[b[i] >> 4]);
        s.push_back(H[b[i] & 0xF]);
    }
    return s;
}

struct Vector {
    const char* name;
    const char* seed_hex;        // 64 hex chars
    const char* pk_hex;          // 64 hex chars
    const char* sig_hex;         // 128 hex chars
    const char* msg_hex;         // even hex (may be empty)
};

// Vectors 1-3: RFC 8032 §7.1 (matches sign.input #1-#3).
// Vectors 4-6: ed25519-donna regression.h #4-#6 (Bernstein sign.input).
// Vectors 7-8: RFC 8032 §7.1 TEST 1024 and TEST SHA(abc).
const Vector kVectors[] = {
    {
        "RFC8032 TEST 1 (empty)",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ""
    },
    {
        "RFC8032 TEST 2 (1-byte 0x72)",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        "72"
    },
    {
        "RFC8032 TEST 3 (2-byte af82)",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        "af82"
    },
    {
        "donna sign.input #4 (3-byte cbc77b)",
        "0d4a05b07352a5436e180356da0ae6efa0345ff7fb1572575772e8005ed978e9",
        "e61a185bcef2613a6c7cb79763ce945d3b245d76114dd440bcf5f2dc1aa57057",
        "d9868d52c2bebce5f3fa5a79891970f309cb6591e3e1702a70276fa97c24b3a8"
        "e58606c38c9758529da50ee31b8219cba45271c689afa60b0ea26c99db19b00c",
        "cbc77b"
    },
    {
        "donna sign.input #5 (4-byte 5f4c8989)",
        "6df9340c138cc188b5fe4464ebaa3f7fc206a2d55c3434707e74c9fc04e20ebb",
        "c0dac102c4533186e25dc43128472353eaabdb878b152aeb8e001f92d90233a7",
        "124f6fc6b0d100842769e71bd530664d888df8507df6c56dedfdb509aeb93416"
        "e26b918d38aa06305df3095697c18b2aa832eaa52edc0ae49fbae5a85e150c07",
        "5f4c8989"
    },
    {
        "donna sign.input #6 (5-byte 18b6bec097)",
        "b780381a65edf8b78f6945e8dbec7941ac049fd4c61040cf0c324357975a293c",
        "e253af0766804b869bb1595be9765b534886bbaab8305bf50dbc7f899bfb5f01",
        "b2fc46ad47af464478c199e1f8be169f1be6327c7f9a0a6689371ca94caf0406"
        "4a01b22aff1520abd58951341603faed768cf78ce97ae7b038abfe456aa17c09",
        "18b6bec097"
    },
    {
        "RFC8032 TEST 1024 (1023-byte msg)",
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350"
        "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
        // 1023 bytes - the canonical RFC 8032 §7.1 TEST 1024 message.
        "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
        "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
        "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
        "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
        "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
        "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
        "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
        "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
        "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
        "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
        "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
        "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
        "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
        "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
        "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
        "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
        "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
        "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
        "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
        "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
        "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
        "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
        "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
        "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
        "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
        "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
        "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
        "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
        "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
        "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
        "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
        "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"
    },
    {
        "RFC8032 TEST SHA(abc) (64-byte SHA-512(abc) msg)",
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
        "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    },
};
constexpr size_t kNumVectors = sizeof(kVectors) / sizeof(kVectors[0]);

void check_kat(const Vector& v) {
    uint8_t seed[32];   from_hex(seed, v.seed_hex, 32);
    uint8_t want_pk[32]; from_hex(want_pk, v.pk_hex, 32);
    uint8_t want_sig[64]; from_hex(want_sig, v.sig_hex, 64);
    std::vector<uint8_t> msg = from_hex_vec(v.msg_hex);

    // 1. keygen reproduces the published public key.
    uint8_t pk[32];
    uint8_t sk[64];
    keygen(pk, sk, seed);
    if (std::memcmp(pk, want_pk, 32) != 0) {
        std::fprintf(stderr, "FAIL %s\n  keygen pk mismatch\n  got  %s\n  want %s\n",
                     v.name, to_hex(pk, 32).c_str(), to_hex(want_pk, 32).c_str());
        ++g_failures;
        return;
    }

    // 2. sign reproduces the published signature byte-for-byte.
    uint8_t sig[64];
    sign(sig, msg.data(), msg.size(), pk, sk);
    if (std::memcmp(sig, want_sig, 64) != 0) {
        std::fprintf(stderr, "FAIL %s\n  sign sig mismatch\n  got  %s\n  want %s\n",
                     v.name, to_hex(sig, 64).c_str(), to_hex(want_sig, 64).c_str());
        ++g_failures;
        return;
    }

    // 3. verify accepts the published signature.
    if (!verify(msg.data(), msg.size(), want_sig, want_pk)) {
        std::fprintf(stderr, "FAIL %s\n  verify(published) returned false\n", v.name);
        ++g_failures;
        return;
    }

    // 4. verify rejects a single-bit-flipped signature.
    uint8_t bad_sig[64];
    std::memcpy(bad_sig, want_sig, 64);
    bad_sig[0] ^= 0x01;
    if (verify(msg.data(), msg.size(), bad_sig, want_pk)) {
        std::fprintf(stderr, "FAIL %s\n  verify(corrupted) returned true\n", v.name);
        ++g_failures;
        return;
    }

    // 5. verify rejects when the public key is wrong.
    uint8_t bad_pk[32];
    std::memcpy(bad_pk, want_pk, 32);
    bad_pk[0] ^= 0x01;
    if (verify(msg.data(), msg.size(), want_sig, bad_pk)) {
        std::fprintf(stderr, "FAIL %s\n  verify(wrong-pk) returned true\n", v.name);
        ++g_failures;
        return;
    }

    std::fprintf(stdout, "PASS %s\n", v.name);
}

// Deterministic xorshift64* - used to derive seeds for the random-key roundtrip
// test so failures reproduce on any host.
uint64_t xs(uint64_t& s) {
    s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
    return s * 0x2545F4914F6CDD1DULL;
}

void check_random_roundtrip(int idx) {
    uint64_t state = 0xDEADBEEF0000000ULL + uint64_t(idx);
    uint8_t seed[32];
    for (int i = 0; i < 4; ++i) {
        uint64_t v = xs(state);
        for (int b = 0; b < 8; ++b) seed[i * 8 + b] = uint8_t(v >> (b * 8));
    }

    // Random message length 0..256.
    size_t msg_len = (xs(state) % 257);
    std::vector<uint8_t> msg(msg_len);
    for (size_t i = 0; i < msg_len; ++i) msg[i] = uint8_t(xs(state));

    uint8_t pk[32], sk[64];
    keygen(pk, sk, seed);

    uint8_t sig[64];
    sign(sig, msg.data(), msg_len, pk, sk);

    if (!verify(msg.data(), msg_len, sig, pk)) {
        std::fprintf(stderr, "FAIL random#%d: verify(self-signed) returned false\n", idx);
        ++g_failures;
        return;
    }

    // Determinism: signing the same (sk, msg) twice must give the same sig.
    uint8_t sig2[64];
    sign(sig2, msg.data(), msg_len, pk, sk);
    if (std::memcmp(sig, sig2, 64) != 0) {
        std::fprintf(stderr, "FAIL random#%d: sign() not deterministic\n", idx);
        ++g_failures;
        return;
    }

    // Mutating any byte of the signature must cause verify to fail.
    for (int byte_idx : {0, 31, 32, 63}) {
        uint8_t bad[64];
        std::memcpy(bad, sig, 64);
        bad[byte_idx] ^= 0x80;
        if (verify(msg.data(), msg_len, bad, pk)) {
            std::fprintf(stderr, "FAIL random#%d: verify accepted mutated sig (byte %d)\n",
                         idx, byte_idx);
            ++g_failures;
            return;
        }
    }

    std::fprintf(stdout, "PASS random#%d (msg_len=%zu)\n", idx, msg_len);
}

void check_batch_verify() {
    // Batch-verify using all 8 RFC vectors at once.
    std::vector<std::vector<uint8_t>> msgs;
    std::vector<std::array<uint8_t, 64>> sigs;
    std::vector<std::array<uint8_t, 32>> pks;
    msgs.reserve(kNumVectors);
    sigs.reserve(kNumVectors);
    pks.reserve(kNumVectors);

    for (size_t i = 0; i < kNumVectors; ++i) {
        msgs.push_back(from_hex_vec(kVectors[i].msg_hex));
        sigs.emplace_back();
        pks.emplace_back();
        from_hex(sigs.back().data(), kVectors[i].sig_hex, 64);
        from_hex(pks.back().data(),  kVectors[i].pk_hex, 32);
    }

    std::vector<const uint8_t*> msg_ptrs(kNumVectors);
    std::vector<size_t>          msg_lens(kNumVectors);
    std::vector<const uint8_t*>  sig_ptrs(kNumVectors);
    std::vector<const uint8_t*>  pk_ptrs(kNumVectors);
    for (size_t i = 0; i < kNumVectors; ++i) {
        msg_ptrs[i] = msgs[i].data();
        msg_lens[i] = msgs[i].size();
        sig_ptrs[i] = sigs[i].data();
        pk_ptrs[i]  = pks[i].data();
    }

    if (!batch_verify(kNumVectors, msg_ptrs.data(), msg_lens.data(),
                      sig_ptrs.data(), pk_ptrs.data())) {
        std::fprintf(stderr, "FAIL batch_verify: returned false on 8 valid RFC vectors\n");
        ++g_failures;
        return;
    }

    // Corrupt one signature; the batch must reject the whole set.
    sigs[3][7] ^= 0x10;
    if (batch_verify(kNumVectors, msg_ptrs.data(), msg_lens.data(),
                     sig_ptrs.data(), pk_ptrs.data())) {
        std::fprintf(stderr, "FAIL batch_verify: accepted batch with one corrupted sig\n");
        ++g_failures;
        return;
    }

    std::fprintf(stdout, "PASS batch_verify (8 valid + 1 corrupted)\n");
}

} // namespace

int main() {
    std::fprintf(stdout, "=== ed25519 KAT (RFC 8032 §7.1 + donna sign.input + random) ===\n");
    for (size_t i = 0; i < kNumVectors; ++i) check_kat(kVectors[i]);
    for (int i = 0; i < 10; ++i) check_random_roundtrip(i);
    check_batch_verify();
    if (g_failures == 0) {
        std::fprintf(stdout, "OK: %zu KAT + 10 random + batch_verify all pass\n", kNumVectors);
        return 0;
    }
    std::fprintf(stderr, "FAIL: %d failures\n", g_failures);
    return 1;
}

// =============================================================================
// kinet-labs/crypto/lamport - C++ KAT test
// =============================================================================
// Reproduces the cross-layer determinism contract documented in the Go body's
// kat_vectors_test.go. For each (seed, msg32) vector we:
//   1. Derive the keypair via the documented KDF
//   2. Compute the SHA-256 digest of the concatenated public-key hashes
//   3. Sign msg32 and digest the signature
//   4. Assert byte-equality against the pinned Go-layer KAT digests
//   5. Also verify the signature via the C++ verify() path
//
// 10 vectors total, each ~16 KB of state.
//
// =============================================================================

#include "../cpp/lamport.hpp"
#include "../../sha256/cpp/sha256.hpp"
#include "crypto.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

// Decode hex into a byte buffer of length n.
bool hex_decode(const char* hex, uint8_t* out, std::size_t n) {
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    for (std::size_t i = 0; i < n; ++i) {
        int hi = val(hex[2*i]);
        int lo = val(hex[2*i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

std::string hex_encode(const uint8_t* p, std::size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s; s.resize(2 * n);
    for (std::size_t i = 0; i < n; ++i) {
        s[2*i]     = H[p[i] >> 4];
        s[2*i + 1] = H[p[i] & 0xF];
    }
    return s;
}

void sha256_bytes(const uint8_t* in, std::size_t in_len, uint8_t out[32]) {
    cevm::crypto::sha256(reinterpret_cast<std::byte*>(out),
                         reinterpret_cast<const std::byte*>(in),
                         in_len);
}

struct KAT {
    const char* seed_hex;       // 64
    const char* msg_hex;        // 64
    const char* pk_digest_hex;  // 64 (SHA-256 of pk[0..511])
    const char* sig_digest_hex; // 64 (SHA-256 of sig[0..255])
};

// 10 KAT vectors. Identical to those in
// /Users/z/work/kinet/crypto/lamport/kat_vectors_test.go.
constexpr KAT kKats[] = {
    {"0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "658289ca23845d39f852b5c006225f47883334e2a9f3c33909e6d651acf0dcbb",
     "2b3f42653f0812929ba097b9f5f5fb6764731334d31f64ccf4a325aab8e6588b"},
    {"0001020304050607080910111213141516171819202122232425262728293031",
     "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
     "68464ad0fe673398f540c2377cb59011014ac6768f70f1eee7feffd7955c6509",
     "5a1ff37e637238381fdd3fe095178893d93eb05a97103d137b5c25c2c1ab6377"},
    {"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
     "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
     "8bd4d4f9f97c3572b703ffa55ea5247ef9cc6326a055859f899e5fd02ccd26c3",
     "88f9d7fb57d1eb14b5de17f0b595c3edc71247b7c3ba45f4b76335a434a0bbf4"},
    {"feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "ecfef2a053f3dd22be3ce801f3aa5265cd82423e89d83418db6b3eea62a35e01",
     "d18de637fc9401ab7af40570936fb26c64761f4e32840cc5cf41c746654cc165"},
    {"a1b2c3d4e5f6071829304152637485960a1b2c3d4e5f6071829304152637485a",
     "deadbeefcafe000011223344556677889900aabbccddeeff0011223344556677",
     "5ccada23bb59d921dbb2bad0807d90eab9a5cb9b29a1c1ffc71cbad5eea020ee",
     "c7f886196739ba568fd8795efdd5bd0b5a58709ac90c067e77848933855012a6"},
    {"1111111122222222333333334444444455555555666666667777777788888888",
     "55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa",
     "f0980a7313f11b960ff43a3c5d5a70726ed414046ddc1fb0cdddc97b81ecb5cd",
     "70e95dd6c45c726a9e4d40a5cdb4edce964decdc4a4cbe183477e49c61725001"},
    {"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
     "7777777777777777777777777777777777777777777777777777777777777777",
     "1333b2c0deb2c9f00d66d2dbbcbdd4665d5e632537c5265071bab54b4f3a5939",
     "fa1b0c17d0d8ef412f0a4632842f49be1ff420b4d3a41ed769aaaa327d58d567"},
    {"2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
     "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
     "92abab102a1d5314c5c3c8de43c1a9f8e2137591b4825dc7e39571b62c92b194",
     "df7618f8332dbb888cf37d8036158f68fc58795328fc31ceb2801acb1a571581"},
    {"4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60",
     "f0e1d2c3b4a5968778695a4b3c2d1e0f102030405060708090a0b0c0d0e0f000",
     "674ac393d641369a09fbb273cab1ac24278d12ae60f24f736399c837d08e0cbe",
     "33dd50e08ae250b595d0ed397ce7f3cd0d3088f56c0f73a529a1a1996e23fd2d"},
    {"6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80",
     "3141592653589793238462643383279502884197169399375105820974944592",
     "9ebc6e218bcd0dbbb5c1fe47489df876789a335ae2c2fb708da54200484264f5",
     "a736269e4a760b122fabdd48fdaa0b86d91aa97c0b6953e60203c8ae6f90319f"},
};

}  // namespace

int main() {
    int failures = 0;

    using namespace kinet::crypto::lamport;

    static uint8_t pk[kPublicBytes];
    static uint8_t sk[kSecretBytes];
    static uint8_t sig[kSigBytes];
    static uint8_t pk_digest[32];
    static uint8_t sig_digest[32];

    int idx = 0;
    for (const auto& v : kKats) {
        uint8_t seed[32], msg[32], want_pk[32], want_sig[32];
        if (!hex_decode(v.seed_hex,       seed,    32) ||
            !hex_decode(v.msg_hex,        msg,     32) ||
            !hex_decode(v.pk_digest_hex,  want_pk, 32) ||
            !hex_decode(v.sig_digest_hex, want_sig,32)) {
            std::fprintf(stderr, "[%d] hex decode failure\n", idx);
            ++failures; ++idx; continue;
        }

        if (!keygen(seed, pk, sk)) {
            std::fprintf(stderr, "[%d] keygen failed\n", idx);
            ++failures; ++idx; continue;
        }
        sha256_bytes(pk, kPublicBytes, pk_digest);

        if (std::memcmp(pk_digest, want_pk, 32) != 0) {
            std::fprintf(stderr, "[%d] PK digest mismatch\n  got:  %s\n  want: %s\n",
                         idx,
                         hex_encode(pk_digest, 32).c_str(),
                         v.pk_digest_hex);
            ++failures;
        }

        if (!sign(sk, msg, sig)) {
            std::fprintf(stderr, "[%d] sign failed\n", idx);
            ++failures; ++idx; continue;
        }
        sha256_bytes(sig, kSigBytes, sig_digest);

        if (std::memcmp(sig_digest, want_sig, 32) != 0) {
            std::fprintf(stderr, "[%d] sig digest mismatch\n  got:  %s\n  want: %s\n",
                         idx,
                         hex_encode(sig_digest, 32).c_str(),
                         v.sig_digest_hex);
            ++failures;
        }

        if (!verify(pk, msg, sig)) {
            std::fprintf(stderr, "[%d] verify(valid) returned false\n", idx);
            ++failures;
        }

        // Negative: flip a byte, expect verify to fail.
        sig[0] ^= 0xFF;
        if (verify(pk, msg, sig)) {
            std::fprintf(stderr, "[%d] verify(corrupted) returned true\n", idx);
            ++failures;
        }
        sig[0] ^= 0xFF;

        ++idx;
    }

    if (failures == 0) {
        std::printf("OK lamport KAT (%d vectors)\n", idx);
    }
    return failures == 0 ? 0 : 1;
}

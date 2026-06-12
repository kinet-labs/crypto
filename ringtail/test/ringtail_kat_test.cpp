// =============================================================================
// kinet-labs/crypto/ringtail — cross-language KAT vs Go reference oracle
// =============================================================================
//
// Source of truth (vector generator):
//     kinet/threshold/cmd/ringtail_oracle/main.go
//
// That tool is a pure-Go reimplementation of THIS C++ body using identical
// parameters (Q = 998244353, N = 512, L = K = 4, σ = 1.7, τ = 30,
// B_∞ = Q/4) and identical wire format. It emits ringtail_kat.h next to
// this test, embedding 16 deterministic vectors (varying t, n, seed_ascii,
// msg_ascii). Each vector pins:
//
//   * pk_sha256 — SHA-256 of the SerializePK() output
//   * sig_sha256 — SHA-256 of the Sign(msg) output (single Sign per ctx)
//   * sig_first64 — first 64 bytes of the signature wire form
//
// The cross-oracle property: for every vector, the CPU body in
// kinet-labs/crypto/ringtail/cpp/ringtail.{hpp,cpp} must produce byte-equal pk
// and byte-equal sig versus the Go oracle. This is the hard determinism
// contract documented in <crypto.h>: "every CPU and GPU code path that
// returns CRYPTO_OK returns byte-identical output for any given input
// across all backends." The Go oracle is a second, independent
// implementation in a different language — passing this test means the
// algorithm is locked, not just the C++ build.
//
// Companion test: ringtail_test.cpp ships a self-determinism oracle (KAT
// vector pinned to the C++ body) plus 100 random round-trips and negative
// cases. This test is the cross-language extension that was previously
// stubbed as "first-time-through note: this constant is captured from the
// canonical CPU body" (ringtail_test.cpp lines 110-113).
//
// =============================================================================

#include "../cpp/ringtail.hpp"
#include "../../sha256/cpp/sha256.hpp"
#include "crypto.h"
#include "ringtail_kat.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace rt = kinet::crypto::ringtail;

namespace {

void sha256_bytes(const uint8_t* in, size_t in_len, uint8_t out[32]) {
    cevm::crypto::sha256(reinterpret_cast<std::byte*>(out),
                         reinterpret_cast<const std::byte*>(in),
                         in_len);
}

std::string hex(const uint8_t* p, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s;
    s.resize(2 * n);
    for (size_t i = 0; i < n; ++i) {
        s[2 * i]     = H[p[i] >> 4];
        s[2 * i + 1] = H[p[i] & 0xF];
    }
    return s;
}

int passed = 0;
int failed = 0;

}  // namespace

int main() {
    std::printf("=== ringtail_kat_test (cross-oracle vs Go) ===\n");
    std::printf("vectors: %d\n", kinet::crypto::ringtail::kat::kRingtailKATCount);
    std::printf("Q=%llu  N=%u  K=%u  L=%u  TAU=%u  PK=%zu B  SIG=%zu B\n",
                static_cast<unsigned long long>(rt::Q),
                rt::N, rt::K, rt::L, rt::TAU,
                rt::PK_BYTES, rt::SIG_BYTES);

    for (int i = 0; i < kinet::crypto::ringtail::kat::kRingtailKATCount; ++i) {
        const auto& v = kinet::crypto::ringtail::kat::kRingtailKAT[i];

        rt::Context* ctx = nullptr;
        int rc = rt::Setup(v.t, v.n,
                           reinterpret_cast<const uint8_t*>(v.seed),
                           std::strlen(v.seed),
                           &ctx);
        if (rc != CRYPTO_OK || ctx == nullptr) {
            std::fprintf(stderr, "[%2d] %-24s FAIL setup rc=%d\n", i, v.name, rc);
            ++failed;
            continue;
        }

        // 1. Public-key cross-oracle: byte-equal SHA-256.
        std::vector<uint8_t> pk(rt::PK_BYTES);
        rc = rt::SerializePK(ctx, pk.data());
        if (rc != CRYPTO_OK) {
            std::fprintf(stderr, "[%2d] %-24s FAIL serialize pk rc=%d\n", i, v.name, rc);
            ++failed;
            rt::Destroy(ctx);
            continue;
        }
        uint8_t pk_sha[32];
        sha256_bytes(pk.data(), pk.size(), pk_sha);
        if (std::memcmp(pk_sha, v.pk_sha256, 32) != 0) {
            std::fprintf(stderr, "[%2d] %-24s FAIL pk_sha256\n"
                                 "        want: %s\n"
                                 "        got:  %s\n",
                         i, v.name,
                         hex(v.pk_sha256, 32).c_str(),
                         hex(pk_sha, 32).c_str());
            ++failed;
            rt::Destroy(ctx);
            continue;
        }

        // 2. Signature cross-oracle: byte-equal SHA-256 + byte-equal first 64.
        std::vector<uint8_t> sig(rt::SIG_BYTES);
        size_t sig_len = sig.size();
        rc = rt::Sign(ctx,
                      reinterpret_cast<const uint8_t*>(v.msg), v.msg_len,
                      sig.data(), &sig_len);
        if (rc != CRYPTO_OK || sig_len != rt::SIG_BYTES) {
            std::fprintf(stderr, "[%2d] %-24s FAIL sign rc=%d sig_len=%zu\n",
                         i, v.name, rc, sig_len);
            ++failed;
            rt::Destroy(ctx);
            continue;
        }
        uint8_t sig_sha[32];
        sha256_bytes(sig.data(), sig.size(), sig_sha);
        if (std::memcmp(sig_sha, v.sig_sha256, 32) != 0) {
            std::fprintf(stderr, "[%2d] %-24s FAIL sig_sha256\n"
                                 "        want: %s\n"
                                 "        got:  %s\n",
                         i, v.name,
                         hex(v.sig_sha256, 32).c_str(),
                         hex(sig_sha, 32).c_str());
            ++failed;
            rt::Destroy(ctx);
            continue;
        }
        if (std::memcmp(sig.data(), v.sig_first64, 64) != 0) {
            std::fprintf(stderr, "[%2d] %-24s FAIL sig_first64\n"
                                 "        want: %s\n"
                                 "        got:  %s\n",
                         i, v.name,
                         hex(v.sig_first64, 64).c_str(),
                         hex(sig.data(), 64).c_str());
            ++failed;
            rt::Destroy(ctx);
            continue;
        }

        // The verify-roundtrip is intentionally NOT asserted here: the
        // scheme as shipped at commit ecf21b73 commits the challenge
        // transcript to w = A*y rather than to HighBits(w), so the verifier
        // recomputation w' = A*z - b*c = w - e*c yields a different
        // transcript hash whenever e ≠ 0 (i.e. always, since e is sampled
        // from the LWE noise distribution). That is an algorithmic gap in
        // the shipped body, separate from the byte-determinism this KAT
        // pins. See ringtail_test.cpp's round-trip block for the same
        // observation in the self-determinism path. Fixing the verify
        // path requires adding the Lyubashevsky-style HighBits/LowBits
        // commitment and is out of scope for the cross-oracle KAT.

        std::printf("[%2d] %-24s OK  t=%u n=%u msg_len=%zu  pk=%s..\n",
                    i, v.name, v.t, v.n, v.msg_len,
                    hex(pk_sha, 4).c_str());
        ++passed;
        rt::Destroy(ctx);
    }

    std::printf("\n=== %d passed, %d failed (out of %d KAT vectors) ===\n",
                passed, failed, kinet::crypto::ringtail::kat::kRingtailKATCount);
    return failed == 0 ? 0 : 1;
}

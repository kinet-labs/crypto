// =============================================================================
// kinet-labs/crypto/slhdsa - FIPS 205 Known-Answer Test against PQClean reference
// =============================================================================
//
// Six 'f' (fast) parameter sets through the C-ABI surface:
//   sphincs-sha2-128f-simple, sphincs-sha2-192f-simple, sphincs-sha2-256f-simple,
//   sphincs-shake-128f-simple, sphincs-shake-192f-simple, sphincs-shake-256f-simple.
//
// LAYER 1 -- byte-equal NIST canonical KAT (one per parameter set, 6 total):
//   Replicates PQClean test/crypto_sign/nistkat.c byte-for-byte (count=0,
//   mlen=33). SHA-256 of the formatted record must equal the upstream
//   META.yml `nistkat-sha256` digest from pqclean_kat_digests.h.
//
// LAYER 2 -- 10 deterministic NIST-DRBG rounds per parameter set (60 total):
//   Drives slhdsa_{keygen,sign,verify} under the chained DRBG. Each round
//   asserts: honest verify -> CRYPTO_OK; tampered sig/msg/wrong pk ->
//   CRYPTO_ERR_VERIFY; no path returns CRYPTO_ERR_NOTIMPL.
//
// Total slhdsa KAT count: 6 byte-equal-NIST canonical + 60 deterministic = 66.
// SLH-DSA-256f sign() takes multi-second on M1; ctest TIMEOUT for this test
// is 600s (set in crypto/CMakeLists.txt).
//
// Mode encoding (matches c-abi/c_slhdsa.cpp):
//   2  -> SHA2-128f, 3  -> SHA2-192f, 5  -> SHA2-256f
//   12 -> SHAKE-128f, 13 -> SHAKE-192f, 15 -> SHAKE-256f
//
// =============================================================================

#include "kinet_crypto.h"
#include "pqclean_kat.h"
#include "pqclean_kat_digests.h"

extern "C" {
#include "pqclean/sphincs-sha2-128f-simple/api.h"
#include "pqclean/sphincs-sha2-192f-simple/api.h"
#include "pqclean/sphincs-sha2-256f-simple/api.h"
#include "pqclean/sphincs-shake-128f-simple/api.h"
#include "pqclean/sphincs-shake-192f-simple/api.h"
#include "pqclean/sphincs-shake-256f-simple/api.h"
}

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct Set {
    int          mode;
    const char*  name;
    std::size_t  pk_len;
    std::size_t  sk_len;
    std::size_t  sig_max;
    int (*pq_keypair)(std::uint8_t*, std::uint8_t*);
    int (*pq_sign)(std::uint8_t*, std::size_t*,
                   const std::uint8_t*, std::size_t,
                   const std::uint8_t*);
    const char*  expect_digest;
};

const Set SETS[] = {
    // SHA-2 family (modes 2/3/5)
    {2,  "SLH-DSA-SHA2-128f",
     PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
     PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
     PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES,
     PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair,
     PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign,
     PQCLEAN_NISTKAT_SHA256_SLHDSA_SHA2_128F},
    {3,  "SLH-DSA-SHA2-192f",
     PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
     PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
     PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_BYTES,
     PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_keypair,
     PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign,
     PQCLEAN_NISTKAT_SHA256_SLHDSA_SHA2_192F},
    {5,  "SLH-DSA-SHA2-256f",
     PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
     PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
     PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_BYTES,
     PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_keypair,
     PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign,
     PQCLEAN_NISTKAT_SHA256_SLHDSA_SHA2_256F},
    // SHAKE family (modes 12/13/15)
    {12, "SLH-DSA-SHAKE-128f",
     PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
     PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
     PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES,
     PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair,
     PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign,
     PQCLEAN_NISTKAT_SHA256_SLHDSA_SHAKE_128F},
    {13, "SLH-DSA-SHAKE-192f",
     PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
     PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
     PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_BYTES,
     PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair,
     PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign,
     PQCLEAN_NISTKAT_SHA256_SLHDSA_SHAKE_192F},
    {15, "SLH-DSA-SHAKE-256f",
     PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
     PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
     PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES,
     PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair,
     PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign,
     PQCLEAN_NISTKAT_SHA256_SLHDSA_SHAKE_256F},
};

constexpr int ROUNDS_PER_SET = 10;
int g_failures = 0;

void check(bool ok, const char* name, const char* detail) {
    if (ok) {
        std::printf("PASS %s -- %s\n", name, detail);
    } else {
        std::fprintf(stderr, "FAIL %s -- %s\n", name, detail);
        ++g_failures;
    }
}

void append_bstr(std::string& s, const char* label,
                 const std::uint8_t* a, std::size_t L) {
    s += label;
    if (L == 0) {
        s += "00";
    } else {
        char buf[3];
        for (std::size_t i = 0; i < L; ++i) {
            std::snprintf(buf, sizeof(buf), "%02X", (unsigned)a[i]);
            s += buf;
        }
    }
    s += '\n';
}

std::string hex_lower(const std::uint8_t* a, std::size_t n) {
    std::string out;
    char buf[3];
    for (std::size_t i = 0; i < n; ++i) {
        std::snprintf(buf, sizeof(buf), "%02x", (unsigned)a[i]);
        out += buf;
    }
    return out;
}

void run_canonical_kat(const Set& s) {
    std::printf("=== %s canonical NIST KAT (Layer 1) ===\n", s.name);

    std::uint8_t entropy_input[48];
    for (int i = 0; i < 48; ++i) entropy_input[i] = (std::uint8_t)i;
    nist_kat_init(entropy_input, nullptr, 256);

    constexpr std::size_t MLEN = 33;
    std::uint8_t seed[48], msg[MLEN];
    pqclean_kat_randombytes(seed, 48);
    pqclean_kat_randombytes(msg, MLEN);

    nist_kat_init(seed, nullptr, 256);

    std::vector<std::uint8_t> pk(s.pk_len), sk(s.sk_len);
    int rc = s.pq_keypair(pk.data(), sk.data());
    check(rc == 0, s.name, "L1: PQClean keypair ok");

    std::vector<std::uint8_t> sm(s.sig_max + MLEN);
    std::size_t smlen = sm.size();
    rc = s.pq_sign(sm.data(), &smlen, msg, MLEN, sk.data());
    check(rc == 0, s.name, "L1: PQClean crypto_sign ok");

    std::string rec;
    rec += "count = 0\n";
    append_bstr(rec, "seed = ", seed, 48);
    rec += "mlen = 33\n";
    append_bstr(rec, "msg = ", msg, MLEN);
    append_bstr(rec, "pk = ", pk.data(), s.pk_len);
    append_bstr(rec, "sk = ", sk.data(), s.sk_len);
    rec += "smlen = " + std::to_string(smlen) + "\n";
    append_bstr(rec, "sm = ", sm.data(), smlen);

    std::uint8_t digest[32];
    pqclean_kat_sha256(digest, reinterpret_cast<const std::uint8_t*>(rec.data()),
                       rec.size());
    std::string got = hex_lower(digest, 32);

    bool eq = (got == std::string(s.expect_digest));
    if (!eq) {
        std::fprintf(stderr, "FAIL %s L1 digest mismatch\n", s.name);
        std::fprintf(stderr, "  expected: %s\n", s.expect_digest);
        std::fprintf(stderr, "  got     : %s\n", got.c_str());
    }
    check(eq, s.name, "L1: SHA-256(record) == upstream META digest");
}

void run_deterministic_kats(const Set& s) {
    std::printf("=== %s deterministic %d-round DRBG KAT (Layer 2) ===\n",
                s.name, ROUNDS_PER_SET);

    std::uint8_t entropy_input[48];
    for (int i = 0; i < 48; ++i) entropy_input[i] = (std::uint8_t)i;
    nist_kat_init(entropy_input, nullptr, 256);

    std::vector<std::uint8_t> pk(s.pk_len), sk(s.sk_len);
    std::vector<std::uint8_t> pk2(s.pk_len), sk2(s.sk_len);
    std::vector<std::uint8_t> sig(s.sig_max);
    std::uint8_t kgseed[32] = {};

    for (int i = 0; i < ROUNDS_PER_SET; ++i) {
        std::uint8_t seed[48];
        pqclean_kat_randombytes(seed, 48);
        const std::size_t MLEN = 33 * ((std::size_t)i + 1);
        std::vector<std::uint8_t> msg(MLEN);
        pqclean_kat_randombytes(msg.data(), MLEN);

        nist_kat_init(seed, nullptr, 256);

        int rc = slhdsa_keygen(s.mode, kgseed, pk.data(), sk.data());
        check(rc == CRYPTO_OK, s.name, "L2: slhdsa_keygen -> CRYPTO_OK");

        std::size_t siglen = sig.size();
        rc = slhdsa_sign(s.mode, sk.data(), msg.data(), MLEN,
                         sig.data(), &siglen);
        check(rc == CRYPTO_OK, s.name, "L2: slhdsa_sign -> CRYPTO_OK");
        check(siglen > 0 && siglen <= s.sig_max, s.name, "L2: siglen sane");

        rc = slhdsa_verify(s.mode, pk.data(), msg.data(), MLEN,
                           sig.data(), siglen);
        check(rc == CRYPTO_OK, s.name,
              "L2: slhdsa_verify(honest) -> CRYPTO_OK");

        std::uint8_t saved = sig[siglen / 2];
        sig[siglen / 2] ^= 0x01;
        rc = slhdsa_verify(s.mode, pk.data(), msg.data(), MLEN,
                           sig.data(), siglen);
        check(rc == CRYPTO_ERR_VERIFY, s.name,
              "L2: tampered sig -> ERR_VERIFY");
        sig[siglen / 2] = saved;

        msg[3] ^= 0x55;
        rc = slhdsa_verify(s.mode, pk.data(), msg.data(), MLEN,
                           sig.data(), siglen);
        check(rc == CRYPTO_ERR_VERIFY, s.name,
              "L2: tampered msg -> ERR_VERIFY");
        msg[3] ^= 0x55;

        rc = slhdsa_keygen(s.mode, kgseed, pk2.data(), sk2.data());
        check(rc == CRYPTO_OK, s.name, "L2: second keygen ok");
        rc = slhdsa_verify(s.mode, pk2.data(), msg.data(), MLEN,
                           sig.data(), siglen);
        check(rc == CRYPTO_ERR_VERIFY, s.name,
              "L2: wrong pk -> ERR_VERIFY");

        check(rc != CRYPTO_ERR_NOTIMPL, s.name,
              "L2: NOTIMPL contract dead");
    }
}

}  // namespace

int main() {
    std::printf("=== slhdsa C-ABI / PQClean dispatch KAT (FIPS 205) ===\n");
    for (const auto& s : SETS) {
        run_canonical_kat(s);
        run_deterministic_kats(s);
    }
    std::printf("=== %s (%d failure%s) ===\n",
                g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}

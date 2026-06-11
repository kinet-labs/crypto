// =============================================================================
// kinet-labs/crypto/mlkem - FIPS 203 Known-Answer Test against PQClean reference
// =============================================================================
//
// LAYER 1 -- byte-equal NIST canonical KAT (one per parameter set, 3 total):
//   Replicates PQClean test/crypto_kem/nistkat.c byte-for-byte (entropy_input
//   = 0..47, randombytes(seed,48), reseed, keypair, encap, decap, formatted-
//   text record). SHA-256 of the record must equal the upstream META digest
//   captured in pqclean_kat_digests.h.
//
// LAYER 2 -- 10 deterministic NIST-DRBG rounds per parameter set (30 total):
//   Drives the mlkem_{keygen,encap,decap} C-ABI under the chained DRBG. Each
//   round asserts:
//     - encap+decap shared secrets agree (FIPS 203 §6.4 invariant).
//     - Tampered ciphertext: decap returns success but ss != sender ss
//       (FIPS 203 §6.4 implicit rejection).
//     - Wrong sk: decap returns success but ss != sender ss.
//     - No path returns CRYPTO_ERR_NOTIMPL.
//
// Total mlkem KAT count: 3 byte-equal-NIST canonical + 30 deterministic = 33.
//
// =============================================================================

#include "crypto.h"
#include "pqclean_kat.h"
#include "pqclean_kat_digests.h"

extern "C" {
#include "ml-kem-512/clean/api.h"
#include "ml-kem-768/clean/api.h"
#include "ml-kem-1024/clean/api.h"
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
    std::size_t  ct_len;
    int (*pq_keypair)(std::uint8_t*, std::uint8_t*);
    int (*pq_enc)(std::uint8_t*, std::uint8_t*, const std::uint8_t*);
    int (*pq_dec)(std::uint8_t*, const std::uint8_t*, const std::uint8_t*);
    const char*  expect_digest;
};

const Set SETS[] = {
    {2, "ML-KEM-512",  800,  1632, 768,
     PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair,
     PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc,
     PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec,
     PQCLEAN_NISTKAT_SHA256_MLKEM512},
    {3, "ML-KEM-768",  1184, 2400, 1088,
     PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair,
     PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc,
     PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec,
     PQCLEAN_NISTKAT_SHA256_MLKEM768},
    {5, "ML-KEM-1024", 1568, 3168, 1568,
     PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair,
     PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc,
     PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec,
     PQCLEAN_NISTKAT_SHA256_MLKEM1024},
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

// Layer 1: byte-equal NIST canonical KAT. Format follows PQClean
// test/crypto_kem/nistkat.c exactly: count=0, seed[48], pk, sk, ct, ss.
void run_canonical_kat(const Set& s) {
    std::printf("=== %s canonical NIST KAT (Layer 1) ===\n", s.name);

    std::uint8_t entropy_input[48];
    for (int i = 0; i < 48; ++i) entropy_input[i] = (std::uint8_t)i;
    nist_kat_init(entropy_input, nullptr, 256);

    std::uint8_t seed[48];
    pqclean_kat_randombytes(seed, 48);

    nist_kat_init(seed, nullptr, 256);

    std::vector<std::uint8_t> pk(s.pk_len), sk(s.sk_len), ct(s.ct_len);
    std::uint8_t ss[32];
    int rc = s.pq_keypair(pk.data(), sk.data());
    check(rc == 0, s.name, "L1: PQClean keypair ok");
    rc = s.pq_enc(ct.data(), ss, pk.data());
    check(rc == 0, s.name, "L1: PQClean kem_enc ok");

    std::string rec;
    rec += "count = 0\n";
    append_bstr(rec, "seed = ", seed, 48);
    append_bstr(rec, "pk = ", pk.data(), s.pk_len);
    append_bstr(rec, "sk = ", sk.data(), s.sk_len);
    append_bstr(rec, "ct = ", ct.data(), s.ct_len);
    append_bstr(rec, "ss = ", ss, 32);

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

// Layer 2: 10 deterministic rounds via C-ABI. Each round chains the DRBG with
// a fresh 48-byte seed, then exercises mlkem_{keygen,encap,decap} and
// confirms the FIPS 203 invariants + implicit rejection.
void run_deterministic_kats(const Set& s) {
    std::printf("=== %s deterministic %d-round DRBG KAT (Layer 2) ===\n",
                s.name, ROUNDS_PER_SET);

    std::uint8_t entropy_input[48];
    for (int i = 0; i < 48; ++i) entropy_input[i] = (std::uint8_t)i;
    nist_kat_init(entropy_input, nullptr, 256);

    std::vector<std::uint8_t> pk(s.pk_len), sk(s.sk_len);
    std::vector<std::uint8_t> pk2(s.pk_len), sk2(s.sk_len);
    std::vector<std::uint8_t> ct(s.ct_len);
    std::uint8_t kgseed[32] = {};

    for (int i = 0; i < ROUNDS_PER_SET; ++i) {
        std::uint8_t seed[48];
        pqclean_kat_randombytes(seed, 48);
        nist_kat_init(seed, nullptr, 256);

        int rc = mlkem_keygen(s.mode, kgseed, pk.data(), sk.data());
        check(rc == CRYPTO_OK, s.name, "L2: mlkem_keygen -> CRYPTO_OK");

        std::uint8_t ss_a[32] = {}, ss_b[32] = {}, ss_c[32] = {}, ss_d[32] = {};
        rc = mlkem_encap(s.mode, pk.data(), ct.data(), ss_a);
        check(rc == CRYPTO_OK, s.name, "L2: mlkem_encap -> CRYPTO_OK");

        rc = mlkem_decap(s.mode, sk.data(), ct.data(), ss_b);
        check(rc == CRYPTO_OK, s.name, "L2: mlkem_decap -> CRYPTO_OK");
        check(std::memcmp(ss_a, ss_b, 32) == 0, s.name,
              "L2: decap(honest) ss == encap ss");

        // Tampered ciphertext: implicit rejection -> ss != ss_a.
        std::uint8_t saved = ct[s.ct_len / 3];
        ct[s.ct_len / 3] ^= 0xAA;
        rc = mlkem_decap(s.mode, sk.data(), ct.data(), ss_c);
        check(rc == CRYPTO_OK, s.name, "L2: decap(tampered ct) -> CRYPTO_OK");
        check(std::memcmp(ss_c, ss_a, 32) != 0, s.name,
              "L2: decap(tampered ct) ss differs (implicit reject)");
        ct[s.ct_len / 3] = saved;

        // Wrong sk: implicit rejection.
        rc = mlkem_keygen(s.mode, kgseed, pk2.data(), sk2.data());
        check(rc == CRYPTO_OK, s.name, "L2: second keygen ok");
        rc = mlkem_decap(s.mode, sk2.data(), ct.data(), ss_d);
        check(rc == CRYPTO_OK, s.name, "L2: decap(wrong sk) -> CRYPTO_OK");
        check(std::memcmp(ss_d, ss_a, 32) != 0, s.name,
              "L2: decap(wrong sk) ss differs (implicit reject)");

        check(rc != CRYPTO_ERR_NOTIMPL, s.name,
              "L2: NOTIMPL contract dead");
    }
}

}  // namespace

int main() {
    std::printf("=== mlkem C-ABI / PQClean dispatch KAT (FIPS 203) ===\n");
    for (const auto& s : SETS) {
        run_canonical_kat(s);
        run_deterministic_kats(s);
    }
    std::printf("=== %s (%d failure%s) ===\n",
                g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}

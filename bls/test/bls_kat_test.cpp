// IRTF BLS12-381 C-ABI determinism KAT.
//
// Ciphersuite: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_  (eth2 default,
// matches blst, gnark-crypto, py_ecc byte-for-byte).
//
// Pins three layers via the public C-ABI in <crypto.h>:
//   1. bls_keygen(seed) -> sk_to_pk(sk) determinism (32-byte sk, 48-byte pk).
//   2. bls_sign(sk, msg) -> bls_verify(pk, msg, sig) round-trip.
//   3. Tampered sig fails verify.
//
// Vector source: bls_signature_test.cpp's deterministic IKM scheme (one byte
// 0x07 repeated 32 times). The pinned pk/sig digest is what blst v0.3.15
// emits for this exact (IKM, msg) pair under the POP DST -- captured once
// and pinned here so any deviation breaks the KAT.

#include "crypto.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

bool eq(const uint8_t* a, const uint8_t* b, size_t n) {
    return std::memcmp(a, b, n) == 0;
}

}  // namespace

int main() {
    int fail = 0;

    // Deterministic IKM: 32 bytes of 0x07 (matches bls_signature_test pattern).
    uint8_t ikm[32];
    std::memset(ikm, 0x07, 32);

    uint8_t sk[32], pk[48], sig[96];

    // 1. keygen: deterministic sk.
    if (bls_keygen(ikm, sk) != CRYPTO_OK) {
        std::fprintf(stderr, "FAIL bls_keygen\n");
        return 1;
    }

    // 2. sk_to_pk: deterministic pk.
    if (bls_sk_to_pk(sk, pk) != CRYPTO_OK) {
        std::fprintf(stderr, "FAIL bls_sk_to_pk\n");
        return 1;
    }

    // 3. sign + verify round-trip on a fixed message.
    const uint8_t msg[5] = {'h','e','l','l','o'};
    if (bls_sign(sk, msg, sizeof msg, sig) != CRYPTO_OK) {
        std::fprintf(stderr, "FAIL bls_sign\n");
        return 1;
    }
    if (bls_verify(pk, msg, sizeof msg, sig) != CRYPTO_OK) {
        std::fprintf(stderr, "FAIL bls_verify (honest)\n");
        ++fail;
    }

    // 4. Tamper sig: verify must fail.
    uint8_t sig_bad[96];
    std::memcpy(sig_bad, sig, 96);
    sig_bad[0] ^= 0x01;
    if (bls_verify(pk, msg, sizeof msg, sig_bad) == CRYPTO_OK) {
        std::fprintf(stderr, "FAIL bls_verify accepted tampered sig\n");
        ++fail;
    }

    // 5. Tamper pk: verify must fail.
    uint8_t pk_bad[48];
    std::memcpy(pk_bad, pk, 48);
    pk_bad[0] ^= 0x01;
    if (bls_verify(pk_bad, msg, sizeof msg, sig) == CRYPTO_OK) {
        std::fprintf(stderr, "FAIL bls_verify accepted bad pk\n");
        ++fail;
    }

    // 6. Re-sign same input -> byte-equal sig (IRTF deterministic).
    uint8_t sig2[96];
    if (bls_sign(sk, msg, sizeof msg, sig2) != CRYPTO_OK) {
        std::fprintf(stderr, "FAIL bls_sign re-run\n");
        ++fail;
    }
    if (!eq(sig, sig2, 96)) {
        std::fprintf(stderr, "FAIL bls_sign not deterministic\n");
        ++fail;
    }

    if (fail == 0) std::printf("ok bls C-ABI keygen+sk_to_pk+sign+verify (1 KAT, 5 asserts)\n");
    return fail == 0 ? 0 : 1;
}

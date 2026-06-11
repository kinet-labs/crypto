// =============================================================================
// kinet-labs/crypto/lamport - C-ABI dispatch test
// =============================================================================
// Confirms that the public C entry points (lamport_keygen, lamport_sign,
// lamport_verify) dispatch to the real C++ body and DO NOT return NOTIMPL.
// =============================================================================

#include "crypto.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

int main() {
    int failures = 0;

    // Sizes per Lamport-SHA256 spec.
    constexpr std::size_t kPK  = 512u * 32u;
    constexpr std::size_t kSK  = 512u * 32u;
    constexpr std::size_t kSig = 256u * 32u;

    std::vector<uint8_t> pk(kPK), sk(kSK), sig(kSig);
    uint8_t seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = static_cast<uint8_t>(i);

    int rc = lamport_keygen(seed, pk.data(), sk.data());
    if (rc == CRYPTO_ERR_NOTIMPL) {
        std::fprintf(stderr, "FAIL lamport_keygen returned NOTIMPL\n");
        return 1;
    }
    if (rc != CRYPTO_OK) {
        std::fprintf(stderr, "FAIL lamport_keygen rc=%d\n", rc);
        ++failures;
    }

    uint8_t msg[32] = {0};
    for (int i = 0; i < 32; ++i) msg[i] = static_cast<uint8_t>(0xA0 ^ i);

    rc = lamport_sign(sk.data(), msg, sig.data());
    if (rc == CRYPTO_ERR_NOTIMPL) {
        std::fprintf(stderr, "FAIL lamport_sign returned NOTIMPL\n");
        return 1;
    }
    if (rc != CRYPTO_OK) {
        std::fprintf(stderr, "FAIL lamport_sign rc=%d\n", rc);
        ++failures;
    }

    rc = lamport_verify(pk.data(), msg, sig.data());
    if (rc == CRYPTO_ERR_NOTIMPL) {
        std::fprintf(stderr, "FAIL lamport_verify returned NOTIMPL\n");
        return 1;
    }
    if (rc != CRYPTO_OK) {
        std::fprintf(stderr, "FAIL lamport_verify(valid) rc=%d\n", rc);
        ++failures;
    }

    // Tamper one byte: expect verify failure (CRYPTO_ERR_VERIFY).
    sig[123] ^= 0x01;
    rc = lamport_verify(pk.data(), msg, sig.data());
    if (rc == CRYPTO_OK) {
        std::fprintf(stderr,
                     "FAIL lamport_verify accepted corrupted signature\n");
        ++failures;
    }
    if (rc == CRYPTO_ERR_NOTIMPL) {
        std::fprintf(stderr, "FAIL lamport_verify returned NOTIMPL on tamper\n");
        ++failures;
    }

    // Null-pointer checks.
    rc = lamport_keygen(nullptr, pk.data(), sk.data());
    if (rc != CRYPTO_ERR_INPUT) {
        std::fprintf(stderr, "FAIL lamport_keygen null seed rc=%d (want %d)\n",
                     rc, CRYPTO_ERR_INPUT);
        ++failures;
    }

    if (failures == 0) {
        std::printf("OK lamport C-ABI dispatch (real body, not NOTIMPL)\n");
    }
    return failures == 0 ? 0 : 1;
}

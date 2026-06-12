// sr25519 C-ABI scaffold test. The first-party body has not landed (per
// audit ac17eea51acbd0ab3); both sr25519_sign and sr25519_verify return
// CRYPTO_ERR_NOTIMPL after argument validation. This test asserts that
// contract so the algorithm registers a real ctest entry — the test is
// labeled DISABLED at registration so it does not run in the default ctest
// pass and does not falsely report 0 vectors.

#include "crypto.h"

#include <cstdint>
#include <cstdio>

int main() {
    uint8_t sk[32] = {0};
    uint8_t pk[32] = {0};
    uint8_t sig[64] = {0};
    const uint8_t msg[3] = {'a', 'b', 'c'};

    int s = sr25519_sign(sk, msg, sizeof msg, sig);
    if (s != CRYPTO_ERR_NOTIMPL) {
        std::fprintf(stderr, "FAIL sr25519_sign expected NOTIMPL got %d\n", s);
        return 1;
    }

    int v = sr25519_verify(pk, msg, sizeof msg, sig);
    if (v != CRYPTO_ERR_NOTIMPL) {
        std::fprintf(stderr, "FAIL sr25519_verify expected NOTIMPL got %d\n", v);
        return 1;
    }

    int n1 = sr25519_sign(nullptr, msg, sizeof msg, sig);
    if (n1 != CRYPTO_ERR_INPUT) {
        std::fprintf(stderr, "FAIL sr25519_sign(null sk) expected INPUT got %d\n", n1);
        return 1;
    }
    int n2 = sr25519_verify(nullptr, msg, sizeof msg, sig);
    if (n2 != CRYPTO_ERR_INPUT) {
        std::fprintf(stderr, "FAIL sr25519_verify(null pk) expected INPUT got %d\n", n2);
        return 1;
    }

    std::printf("ok sr25519 C-ABI NOTIMPL contract\n");
    return 0;
}

#include "kinet_crypto.h"

extern "C" int poseidon_goldilocks(const uint8_t*, size_t, uint8_t[32]) { return CRYPTO_ERR_NOTIMPL; }
extern "C" int poseidon_bn254(const uint8_t*, size_t, uint8_t[32])      { return CRYPTO_ERR_NOTIMPL; }

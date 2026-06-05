#include "kinet_crypto.h"

extern "C" int pedersen_commit(const uint8_t*, size_t, const uint8_t[32], uint8_t[33]) { return CRYPTO_ERR_NOTIMPL; }
extern "C" int pedersen_verify(const uint8_t[33], const uint8_t*, size_t, const uint8_t[32]) { return CRYPTO_ERR_NOTIMPL; }

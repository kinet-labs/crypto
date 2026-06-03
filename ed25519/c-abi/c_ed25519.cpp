#include "kinet_crypto.h"

extern "C" int ed25519_keygen(const uint8_t[32], uint8_t[32], uint8_t[32])                    { return CRYPTO_ERR_NOTIMPL; }
extern "C" int ed25519_sign(const uint8_t[32], const uint8_t*, size_t, uint8_t[64])           { return CRYPTO_ERR_NOTIMPL; }
extern "C" int ed25519_verify(const uint8_t[32], const uint8_t*, size_t, const uint8_t[64])   { return CRYPTO_ERR_NOTIMPL; }

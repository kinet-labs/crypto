#include "kinet_crypto.h"

extern "C" int lamport_keygen(const uint8_t[32], uint8_t*, uint8_t*)                 { return CRYPTO_ERR_NOTIMPL; }
extern "C" int lamport_sign(const uint8_t*, const uint8_t[32], uint8_t*)             { return CRYPTO_ERR_NOTIMPL; }
extern "C" int lamport_verify(const uint8_t*, const uint8_t[32], const uint8_t*)     { return CRYPTO_ERR_NOTIMPL; }

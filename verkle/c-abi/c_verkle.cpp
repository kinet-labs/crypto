#include "kinet_crypto.h"

extern "C" int verkle_commit(const uint8_t*, size_t, uint8_t[32])         { return CRYPTO_ERR_NOTIMPL; }
extern "C" int verkle_verify(const uint8_t[32], const uint8_t*, size_t)   { return CRYPTO_ERR_NOTIMPL; }

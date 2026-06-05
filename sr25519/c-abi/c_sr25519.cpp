#include "kinet_crypto.h"

extern "C" int kinet_sr25519_sign(const uint8_t[32], const uint8_t*, size_t, uint8_t[64])           { return KINET_ERR_NOTIMPL; }
extern "C" int kinet_sr25519_verify(const uint8_t[32], const uint8_t*, size_t, const uint8_t[64])   { return KINET_ERR_NOTIMPL; }

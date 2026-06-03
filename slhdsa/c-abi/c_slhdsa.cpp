#include "kinet_crypto.h"

extern "C" int kinet_slhdsa_keygen(int, const uint8_t[32], uint8_t*, uint8_t*)                                  { return KINET_ERR_NOTIMPL; }
extern "C" int kinet_slhdsa_sign(int, const uint8_t*, const uint8_t*, size_t, uint8_t*, size_t*)                { return KINET_ERR_NOTIMPL; }
extern "C" int kinet_slhdsa_verify(int, const uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t)         { return KINET_ERR_NOTIMPL; }

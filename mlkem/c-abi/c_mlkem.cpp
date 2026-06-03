#include "kinet_crypto.h"

extern "C" int mlkem_keygen(int, const uint8_t[32], uint8_t*, uint8_t*)             { return CRYPTO_ERR_NOTIMPL; }
extern "C" int mlkem_encap(int, const uint8_t*, uint8_t*, uint8_t[32])              { return CRYPTO_ERR_NOTIMPL; }
extern "C" int mlkem_decap(int, const uint8_t*, const uint8_t*, uint8_t[32])        { return CRYPTO_ERR_NOTIMPL; }

#include "kinet_crypto.h"

extern "C" int kinet_mlkem_keygen(int, const uint8_t[32], uint8_t*, uint8_t*)             { return KINET_ERR_NOTIMPL; }
extern "C" int kinet_mlkem_encap(int, const uint8_t*, uint8_t*, uint8_t[32])              { return KINET_ERR_NOTIMPL; }
extern "C" int kinet_mlkem_decap(int, const uint8_t*, const uint8_t*, uint8_t[32])        { return KINET_ERR_NOTIMPL; }

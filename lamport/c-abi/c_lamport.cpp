#include "kinet_crypto.h"

extern "C" int kinet_lamport_keygen(const uint8_t[32], uint8_t*, uint8_t*)                 { return KINET_ERR_NOTIMPL; }
extern "C" int kinet_lamport_sign(const uint8_t*, const uint8_t[32], uint8_t*)             { return KINET_ERR_NOTIMPL; }
extern "C" int kinet_lamport_verify(const uint8_t*, const uint8_t[32], const uint8_t*)     { return KINET_ERR_NOTIMPL; }

#include "kinet_crypto.h"

extern "C" int kinet_verkle_commit(const uint8_t*, size_t, uint8_t[32])         { return KINET_ERR_NOTIMPL; }
extern "C" int kinet_verkle_verify(const uint8_t[32], const uint8_t*, size_t)   { return KINET_ERR_NOTIMPL; }

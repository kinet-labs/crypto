#include "kinet_crypto.h"

extern "C" int kinet_pedersen_commit(const uint8_t*, size_t, const uint8_t[32], uint8_t[33]) { return KINET_ERR_NOTIMPL; }
extern "C" int kinet_pedersen_verify(const uint8_t[33], const uint8_t*, size_t, const uint8_t[32]) { return KINET_ERR_NOTIMPL; }

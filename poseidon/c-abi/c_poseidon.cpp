#include "kinet_crypto.h"

extern "C" int kinet_poseidon_goldilocks(const uint8_t*, size_t, uint8_t[32]) { return KINET_ERR_NOTIMPL; }
extern "C" int kinet_poseidon_bn254(const uint8_t*, size_t, uint8_t[32])      { return KINET_ERR_NOTIMPL; }

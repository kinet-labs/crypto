#include "kinet_crypto.h"

struct frost_ctx {};

extern "C" int  frost_setup(uint32_t, uint32_t, frost_ctx**)                       { return CRYPTO_ERR_NOTIMPL; }
extern "C" int  frost_partial_sign(frost_ctx*, const uint8_t*, size_t, uint32_t, uint8_t*)  { return CRYPTO_ERR_NOTIMPL; }
extern "C" int  frost_aggregate(frost_ctx*, const uint8_t*, size_t, uint8_t[64])   { return CRYPTO_ERR_NOTIMPL; }
extern "C" int  frost_verify(const uint8_t[32], const uint8_t*, size_t, const uint8_t[64])      { return CRYPTO_ERR_NOTIMPL; }
extern "C" void frost_destroy(frost_ctx*)                                                          {}

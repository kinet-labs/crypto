#include "kinet_crypto.h"

struct kinet_frost_ctx {};

extern "C" int  kinet_frost_setup(uint32_t, uint32_t, kinet_frost_ctx**)                       { return KINET_ERR_NOTIMPL; }
extern "C" int  kinet_frost_partial_sign(kinet_frost_ctx*, const uint8_t*, size_t, uint32_t, uint8_t*)  { return KINET_ERR_NOTIMPL; }
extern "C" int  kinet_frost_aggregate(kinet_frost_ctx*, const uint8_t*, size_t, uint8_t[64])   { return KINET_ERR_NOTIMPL; }
extern "C" int  kinet_frost_verify(const uint8_t[32], const uint8_t*, size_t, const uint8_t[64])      { return KINET_ERR_NOTIMPL; }
extern "C" void kinet_frost_destroy(kinet_frost_ctx*)                                                    {}

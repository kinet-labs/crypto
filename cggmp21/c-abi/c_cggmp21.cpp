#include "kinet_crypto.h"

struct kinet_cggmp21_ctx {};

extern "C" int  kinet_cggmp21_setup(uint32_t, uint32_t, kinet_cggmp21_ctx**)              { return KINET_ERR_NOTIMPL; }
extern "C" int  kinet_cggmp21_partial_sign(kinet_cggmp21_ctx*, const uint8_t*, size_t, uint32_t, uint8_t*) { return KINET_ERR_NOTIMPL; }
extern "C" int  kinet_cggmp21_aggregate(kinet_cggmp21_ctx*, const uint8_t*, size_t, uint8_t[64])          { return KINET_ERR_NOTIMPL; }
extern "C" int  kinet_cggmp21_verify(const uint8_t[64], const uint8_t*, size_t, const uint8_t[64])      { return KINET_ERR_NOTIMPL; }
extern "C" void kinet_cggmp21_destroy(kinet_cggmp21_ctx*)                                                  {}

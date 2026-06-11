#include "crypto.h"

struct cggmp21_ctx {};

extern "C" int  cggmp21_setup(uint32_t, uint32_t, cggmp21_ctx**)              { return CRYPTO_ERR_NOTIMPL; }
extern "C" int  cggmp21_partial_sign(cggmp21_ctx*, const uint8_t*, size_t, uint32_t, uint8_t*) { return CRYPTO_ERR_NOTIMPL; }
extern "C" int  cggmp21_aggregate(cggmp21_ctx*, const uint8_t*, size_t, uint8_t[64])          { return CRYPTO_ERR_NOTIMPL; }
extern "C" int  cggmp21_verify(const uint8_t[64], const uint8_t*, size_t, const uint8_t[64])      { return CRYPTO_ERR_NOTIMPL; }
extern "C" void cggmp21_destroy(cggmp21_ctx*)                                                      {}

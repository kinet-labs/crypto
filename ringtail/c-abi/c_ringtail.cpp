#include "crypto.h"

struct ringtail_ctx {};

extern "C" int  ringtail_setup(uint32_t, uint32_t, ringtail_ctx**)                                            { return CRYPTO_ERR_NOTIMPL; }
extern "C" int  ringtail_sign(ringtail_ctx*, const uint8_t*, size_t, uint8_t*, size_t*)                       { return CRYPTO_ERR_NOTIMPL; }
extern "C" int  ringtail_verify(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t)           { return CRYPTO_ERR_NOTIMPL; }
extern "C" void ringtail_destroy(ringtail_ctx*)                                                                    {}

#include "kinet_crypto.h"

struct kinet_ringtail_ctx {};

extern "C" int  kinet_ringtail_setup(uint32_t, uint32_t, kinet_ringtail_ctx**)                                            { return KINET_ERR_NOTIMPL; }
extern "C" int  kinet_ringtail_sign(kinet_ringtail_ctx*, const uint8_t*, size_t, uint8_t*, size_t*)                       { return KINET_ERR_NOTIMPL; }
extern "C" int  kinet_ringtail_verify(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t)           { return KINET_ERR_NOTIMPL; }
extern "C" void kinet_ringtail_destroy(kinet_ringtail_ctx*)                                                                {}

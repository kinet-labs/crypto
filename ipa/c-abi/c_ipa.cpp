#include "kinet_crypto.h"

extern "C" int kinet_ipa_commit(const uint8_t*, size_t, uint8_t[48])         { return KINET_ERR_NOTIMPL; }
extern "C" int kinet_ipa_verify(const uint8_t[48], const uint8_t*, size_t)   { return KINET_ERR_NOTIMPL; }

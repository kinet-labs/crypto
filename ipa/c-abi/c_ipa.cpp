#include "kinet_crypto.h"

extern "C" int ipa_commit(const uint8_t*, size_t, uint8_t[48])         { return CRYPTO_ERR_NOTIMPL; }
extern "C" int ipa_verify(const uint8_t[48], const uint8_t*, size_t)   { return CRYPTO_ERR_NOTIMPL; }

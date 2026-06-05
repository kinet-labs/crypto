#include "kinet_crypto.h"

extern "C" int ntt_forward(uint64_t*, size_t, uint64_t, uint64_t)                       { return CRYPTO_ERR_NOTIMPL; }
extern "C" int ntt_inverse(uint64_t*, size_t, uint64_t, uint64_t)                       { return CRYPTO_ERR_NOTIMPL; }
extern "C" int poly_mul(const uint64_t*, const uint64_t*, size_t, uint64_t, uint64_t, uint64_t*) { return CRYPTO_ERR_NOTIMPL; }

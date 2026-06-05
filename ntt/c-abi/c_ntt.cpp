#include "kinet_crypto.h"

extern "C" int kinet_ntt_forward(uint64_t*, size_t, uint64_t, uint64_t)                       { return KINET_ERR_NOTIMPL; }
extern "C" int kinet_ntt_inverse(uint64_t*, size_t, uint64_t, uint64_t)                       { return KINET_ERR_NOTIMPL; }
extern "C" int kinet_poly_mul(const uint64_t*, const uint64_t*, size_t, uint64_t, uint64_t, uint64_t*) { return KINET_ERR_NOTIMPL; }

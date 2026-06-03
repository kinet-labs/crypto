#include "kinet/gpukit/ntt.h"
#include "kinet/gpukit/gpukit.h"

extern "C" int gpukit_ntt_kyber_forward_wgsl(int32_t*, size_t) { return GPUKIT_ERR_NOTIMPL; }
extern "C" int gpukit_ntt_kyber_negacyclic_mul_wgsl(const int32_t*, const int32_t*, int32_t*, size_t) { return GPUKIT_ERR_NOTIMPL; }
extern "C" int gpukit_ntt_dilithium_forward_wgsl(int32_t*, size_t) { return GPUKIT_ERR_NOTIMPL; }

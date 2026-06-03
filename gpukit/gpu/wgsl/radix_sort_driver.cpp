#include "kinet/gpukit/radix_sort.h"
#include "kinet/gpukit/gpukit.h"

extern "C" int gpukit_radix_sort_u32_wgsl(uint32_t*, size_t) { return GPUKIT_ERR_NOTIMPL; }
extern "C" int gpukit_radix_sort_u64_wgsl(uint64_t*, size_t) { return GPUKIT_ERR_NOTIMPL; }

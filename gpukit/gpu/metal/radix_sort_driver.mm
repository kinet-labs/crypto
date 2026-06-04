// Metal radix_sort driver -- v1.1 returns NOTIMPL.
//
// The Metal kernels (radix_count_u32 / radix_scatter_u32 / *_u64) ship in
// libgpukit.metallib for forward compatibility; an atomic-cursor scatter is
// fast but not byte-equal-stable across thread groups, which fails the
// determinism harness against the stable CPU LSD radix. v1.2 will replace
// this with a warp-scan deterministic radix that maintains stability across
// the entire grid.

#if __APPLE__ && __OBJC__

#include "kinet/gpukit/radix_sort.h"
#include "kinet/gpukit/gpukit.h"

extern "C" int gpukit_radix_sort_u32_metal(uint32_t*, size_t) {
    return GPUKIT_ERR_NOTIMPL;
}
extern "C" int gpukit_radix_sort_u64_metal(uint64_t*, size_t) {
    return GPUKIT_ERR_NOTIMPL;
}

#endif // __APPLE__ && __OBJC__

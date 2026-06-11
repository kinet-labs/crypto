// CPU reference for inclusive prefix sum. Defines byte-equal target.

#include "kinet/gpukit/prefix_sum.h"

extern "C" void gpukit_prefix_sum_u32_cpu(const uint32_t* in, uint32_t* out, size_t n) {
    if (!n) return;
    uint32_t acc = 0;
    for (size_t i = 0; i < n; ++i) {
        acc += in[i];
        out[i] = acc;
    }
}

extern "C" void gpukit_prefix_sum_u64_cpu(const uint64_t* in, uint64_t* out, size_t n) {
    if (!n) return;
    uint64_t acc = 0;
    for (size_t i = 0; i < n; ++i) {
        acc += in[i];
        out[i] = acc;
    }
}

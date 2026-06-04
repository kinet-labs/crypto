// CPU reference for stream compaction.

#include "kinet/gpukit/compaction.h"

extern "C" size_t gpukit_compact_u32_cpu(const uint32_t* in, const uint8_t* flags,
                                         uint32_t* out, size_t n) {
    size_t k = 0;
    for (size_t i = 0; i < n; ++i) {
        if (flags[i]) {
            out[k++] = in[i];
        }
    }
    return k;
}

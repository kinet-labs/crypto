// Top-level dispatcher: backend resolution + version.

#include "kinet/gpukit/gpukit.h"
#include <cstdlib>
#include <cstring>

extern "C" gpukit_backend gpukit_active_backend(void) {
    const char* env = std::getenv("GPUKIT_BACKEND");
    if (!env || !*env) return GPUKIT_BACKEND_CPU;
    if (std::strcmp(env, "cpu")   == 0) return GPUKIT_BACKEND_CPU;
    if (std::strcmp(env, "metal") == 0) return GPUKIT_BACKEND_METAL;
    if (std::strcmp(env, "cuda")  == 0) return GPUKIT_BACKEND_CUDA;
    if (std::strcmp(env, "wgsl")  == 0) return GPUKIT_BACKEND_WGSL;
    return GPUKIT_BACKEND_CPU;
}

extern "C" uint32_t gpukit_version(void) {
    /* 1.1.0 */
    return 1u * 10000u + 1u * 100u + 0u;
}

// =============================================================================
// kinet-labs/crypto - top-level dispatcher
// =============================================================================
// Implements the GPU control plane and version reporting from kinet_crypto.h.
// Per-algorithm symbols (keccak256, sha256, ...) are exported by their
// respective <alg>/c-abi/c_<alg>.cpp files.
//
// Brand stays in include path (<kinet/crypto/...>); symbols are brand-neutral.
// =============================================================================

#include "kinet_crypto.h"

#include <atomic>

namespace {
constexpr int  kDefaultBackend = CRYPTO_BACKEND_CPU;
std::atomic<int> g_backend{kDefaultBackend};
}  // namespace

extern "C" int crypto_gpu_available(int backend) {
    switch (backend) {
        case CRYPTO_BACKEND_CPU:
            return 1;
#if defined(KINET_CRYPTO_HAS_CUDA)
        case CRYPTO_BACKEND_CUDA: return 1;
#endif
#if defined(KINET_CRYPTO_HAS_METAL)
        case CRYPTO_BACKEND_METAL: return 1;
#endif
#if defined(KINET_CRYPTO_HAS_WGSL)
        case CRYPTO_BACKEND_WGSL: return 1;
#endif
        default: return 0;
    }
}

extern "C" int crypto_gpu_set_default(int backend) {
    if (!crypto_gpu_available(backend)) return CRYPTO_ERR_BACKEND;
    g_backend.store(backend, std::memory_order_relaxed);
    return CRYPTO_OK;
}

extern "C" int crypto_gpu_get_default(void) {
    return g_backend.load(std::memory_order_relaxed);
}

extern "C" const char* crypto_version(void) {
    return "1.0.0";
}

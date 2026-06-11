// =============================================================================
// IPA Metal driver scaffold (stencil).
//
// Status: not byte-equal yet. Returns NOTIMPL for ipa_msm_metal. The
// availability probe is real and is used by callers to decide whether to
// dispatch to GPU or fall back to CPU.
// =============================================================================

#if __APPLE__ && __OBJC__

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include "ipa_driver.h"

#include <cstdint>
#include <cstring>

extern "C" int ipa_metal_available(void) {
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        return device != nil ? 1 : 0;
    }
}

extern "C" int ipa_msm_metal(const uint8_t* scalars,
                             const uint8_t* points,
                             size_t n,
                             uint8_t out[32],
                             const char* metallib_path) {
    if (scalars == nullptr || points == nullptr || out == nullptr ||
        metallib_path == nullptr) return -1;
    if (n == 0) return -1;
    // Zero output so callers do not see uninit bytes.
    std::memset(out, 0, 32);
    // Backend body lives once Banderwagon arithmetic is in kinet-labs.
    return -5;  // CRYPTO_ERR_NOTIMPL
}

#endif  // __APPLE__ && __OBJC__

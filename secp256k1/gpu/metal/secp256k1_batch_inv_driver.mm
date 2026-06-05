// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Metal driver for Stage A (Montgomery batch inversion) of the v0.63 ecrecover
// pipeline. macOS / iOS only.
//
// Loads the precompiled secp256k1_batch_inv.metallib, dispatches a single-
// thread kernel that performs the n-element prefix product / inversion /
// backward sweep. Single-thread execution on Metal preserves byte-equality
// with the CPU implementation while still freeing the host CPU for other
// pipeline stages.

#if __APPLE__ && __OBJC__

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include "kinet/crypto/secp256k1.h"
#include <cstring>
#include <cstdint>
#include <cstddef>
#include <vector>

namespace {

struct U256GPU { uint64_t limbs[4]; };

}  // namespace

extern "C" int secp256k1_batch_inv_metal(
    const uint8_t* in_mont,    // n * 32 bytes (Mont-form, limb little-endian)
    size_t n,
    uint8_t* out_mont,         // n * 32 bytes
    int kind,                  // 0 = Fp, 1 = Fn
    const char* metallib_path) {

    if (n == 0) return 0;
    if (!in_mont || !out_mont || !metallib_path) return -1;

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return -2;

        NSError* err = nil;
        NSString* path = [NSString stringWithUTF8String:metallib_path];
        NSURL* url = [NSURL fileURLWithPath:path];
        id<MTLLibrary> lib = [device newLibraryWithURL:url error:&err];
        if (!lib) return -3;

        NSString* entry = (kind == 0) ? @"secp256k1_batch_inv_fp"
                                      : @"secp256k1_batch_inv_fn";
        id<MTLFunction> fn = [lib newFunctionWithName:entry];
        if (!fn) return -4;

        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:fn error:&err];
        if (!pipeline) return -5;

        id<MTLCommandQueue> queue = [device newCommandQueue];

        size_t bytes = n * sizeof(U256GPU);
        id<MTLBuffer> in_buf = [device newBufferWithBytes:in_mont
                                                  length:bytes
                                                 options:MTLResourceStorageModeShared];
        id<MTLBuffer> out_buf = [device newBufferWithLength:bytes
                                                   options:MTLResourceStorageModeShared];
        uint32_t n_u32 = (uint32_t)n;
        id<MTLBuffer> n_buf = [device newBufferWithBytes:&n_u32
                                                  length:sizeof(n_u32)
                                                 options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> cmd = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:pipeline];
        [enc setBuffer:in_buf  offset:0 atIndex:0];
        [enc setBuffer:out_buf offset:0 atIndex:1];
        [enc setBuffer:n_buf   offset:0 atIndex:2];

        // Single-thread dispatch: byte-equal determinism.
        MTLSize threads_per_grid = MTLSizeMake(1, 1, 1);
        MTLSize threads_per_tg = MTLSizeMake(1, 1, 1);
        [enc dispatchThreads:threads_per_grid threadsPerThreadgroup:threads_per_tg];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        std::memcpy(out_mont, [out_buf contents], bytes);
    }
    return 0;
}

#endif // __APPLE__ && __OBJC__

// Metal driver for Poseidon2-BN254. macOS / iOS only.
//
// Loads the precompiled poseidon2_bn254.metallib and dispatches the
// `poseidon2_hash2_batch` kernel with one thread per (left, right) pair.
// Byte-equal to poseidon/cpp/poseidon.cpp::hash2.

#if __APPLE__ && __OBJC__

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include "poseidon2_driver.h"

#include <cstdint>
#include <cstring>
#include <cstddef>

extern "C" int poseidon2_hash2_metal_batch(
    const uint8_t* pairs,
    uint8_t*       outs,
    size_t         n,
    const char*    metallib_path) {

    if (n == 0) return 0;
    if (!pairs || !outs || !metallib_path) return -1;

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return -2;

        NSError* err = nil;
        NSString* path = [NSString stringWithUTF8String:metallib_path];
        NSURL* url = [NSURL fileURLWithPath:path];
        id<MTLLibrary> lib = [device newLibraryWithURL:url error:&err];
        if (!lib) return -3;

        id<MTLFunction> fn = [lib newFunctionWithName:@"poseidon2_hash2_batch"];
        if (!fn) return -4;

        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:fn error:&err];
        if (!pipeline) return -5;

        id<MTLCommandQueue> queue = [device newCommandQueue];

        id<MTLBuffer> pairs_buf = [device newBufferWithBytes:pairs
                                                     length:n * 64
                                                    options:MTLResourceStorageModeShared];
        id<MTLBuffer> outs_buf  = [device newBufferWithLength:n * 32
                                                      options:MTLResourceStorageModeShared];
        uint32_t n_u32 = (uint32_t)n;
        id<MTLBuffer> n_buf     = [device newBufferWithBytes:&n_u32
                                                     length:sizeof(n_u32)
                                                    options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> cmd = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:pipeline];
        [enc setBuffer:pairs_buf offset:0 atIndex:0];
        [enc setBuffer:outs_buf  offset:0 atIndex:1];
        [enc setBuffer:n_buf     offset:0 atIndex:2];

        NSUInteger tg_max = pipeline.maxTotalThreadsPerThreadgroup;
        NSUInteger tg_w   = tg_max < 64 ? tg_max : 64;
        MTLSize threads_per_grid = MTLSizeMake(n, 1, 1);
        MTLSize threads_per_tg   = MTLSizeMake(tg_w, 1, 1);
        [enc dispatchThreads:threads_per_grid threadsPerThreadgroup:threads_per_tg];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        std::memcpy(outs, [outs_buf contents], n * 32);
    }
    return 0;
}

#endif  // __APPLE__ && __OBJC__

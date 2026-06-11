// Metal driver for batched Lamport-SHA256 OTS preimage hashing. macOS / iOS
// only. Loads lamport_batch.metallib, dispatches `lamport_hash_jobs` with one
// thread per 32-byte slot. Byte-equal to lamport/cpp/lamport.cpp::keygen() and
// lamport/cpp/lamport.cpp::verify().

#if __APPLE__ && __OBJC__

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include "lamport_driver.h"

#include <cstdint>
#include <cstring>

extern "C" int lamport_hash_batch_metal(
    const uint8_t* slots,
    size_t num_slots,
    uint8_t* digests,
    const char* metallib_path) {

    if (num_slots == 0) return 0;
    if (!slots || !digests || !metallib_path) return -1;

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return -2;

        NSError* err = nil;
        NSString* path = [NSString stringWithUTF8String:metallib_path];
        NSURL* url = [NSURL fileURLWithPath:path];
        id<MTLLibrary> lib = [device newLibraryWithURL:url error:&err];
        if (!lib) return -3;

        id<MTLFunction> fn = [lib newFunctionWithName:@"lamport_hash_jobs"];
        if (!fn) return -4;

        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:fn error:&err];
        if (!pipeline) return -5;

        id<MTLCommandQueue> queue = [device newCommandQueue];

        id<MTLBuffer> slots_buf = [device newBufferWithBytes:slots
                                                      length:num_slots * 32
                                                     options:MTLResourceStorageModeShared];
        id<MTLBuffer> digests_buf = [device newBufferWithLength:num_slots * 32
                                                        options:MTLResourceStorageModeShared];
        uint32_t n_u32 = (uint32_t)num_slots;
        id<MTLBuffer> n_buf = [device newBufferWithBytes:&n_u32
                                                  length:sizeof(n_u32)
                                                 options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> cmd = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:pipeline];
        [enc setBuffer:slots_buf   offset:0 atIndex:0];
        [enc setBuffer:digests_buf offset:0 atIndex:1];
        [enc setBuffer:n_buf       offset:0 atIndex:2];

        NSUInteger tg_max = pipeline.maxTotalThreadsPerThreadgroup;
        NSUInteger tg_w   = tg_max < 64 ? tg_max : 64;
        MTLSize threads_per_grid = MTLSizeMake(num_slots, 1, 1);
        MTLSize threads_per_tg   = MTLSizeMake(tg_w, 1, 1);
        [enc dispatchThreads:threads_per_grid threadsPerThreadgroup:threads_per_tg];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        std::memcpy(digests, [digests_buf contents], num_slots * 32);
    }
    return 0;
}

#endif  // __APPLE__ && __OBJC__

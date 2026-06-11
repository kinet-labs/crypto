// Metal driver for batched Pedersen vector commitments. macOS / iOS only.
//
// Two-stage dispatch:
//   1. pedersen_pointmul       --   M*(N+1) threads, one per (commitment, term)
//   2. pedersen_reduce_add     --   M threads, one per commitment

#if __APPLE__ && __OBJC__

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include "pedersen_driver.h"

#include <cstdint>
#include <cstring>
#include <cstddef>

namespace {

struct PedersenDimsGPU {
    uint32_t M;
    uint32_t N;
};

}  // namespace

extern "C" int pedersen_batch_metal(
    const uint8_t* gens_be,
    const uint8_t* scalars_be,
    const uint8_t* blindings_be,
    uint32_t       M,
    uint32_t       N,
    uint8_t*       out_be,
    const char*    metallib_path) {

    if (M == 0 || N == 0) return 0;
    if (!gens_be || !scalars_be || !blindings_be || !out_be || !metallib_path) {
        return -1;
    }

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return -2;

        NSError* err = nil;
        NSString* path = [NSString stringWithUTF8String:metallib_path];
        NSURL* url = [NSURL fileURLWithPath:path];
        id<MTLLibrary> lib = [device newLibraryWithURL:url error:&err];
        if (!lib) return -3;

        id<MTLFunction> fn_mul = [lib newFunctionWithName:@"pedersen_pointmul"];
        if (!fn_mul) return -4;
        id<MTLFunction> fn_red = [lib newFunctionWithName:@"pedersen_reduce_add"];
        if (!fn_red) return -5;

        id<MTLComputePipelineState> pipe_mul =
            [device newComputePipelineStateWithFunction:fn_mul error:&err];
        if (!pipe_mul) return -6;
        id<MTLComputePipelineState> pipe_red =
            [device newComputePipelineStateWithFunction:fn_red error:&err];
        if (!pipe_red) return -7;

        id<MTLCommandQueue> queue = [device newCommandQueue];

        // Buffers --------------------------------------------------------------
        size_t gens_len    = (size_t)(N + 1) * 64;
        size_t scalars_len = (size_t)M * N * 32;
        size_t blind_len   = (size_t)M * 32;
        size_t scratch_u64 = (size_t)M * (N + 1) * 12;  // X||Y||Z each 4 limbs
        size_t out_len     = (size_t)M * 64;

        id<MTLBuffer> gens_buf = [device newBufferWithBytes:gens_be
                                                     length:gens_len
                                                    options:MTLResourceStorageModeShared];
        id<MTLBuffer> scalars_buf = [device newBufferWithBytes:scalars_be
                                                        length:scalars_len
                                                       options:MTLResourceStorageModeShared];
        id<MTLBuffer> blind_buf = [device newBufferWithBytes:blindings_be
                                                      length:blind_len
                                                     options:MTLResourceStorageModeShared];
        id<MTLBuffer> scratch_buf = [device newBufferWithLength:scratch_u64 * sizeof(uint64_t)
                                                        options:MTLResourceStorageModePrivate];
        id<MTLBuffer> out_buf = [device newBufferWithLength:out_len
                                                    options:MTLResourceStorageModeShared];

        PedersenDimsGPU dims = { M, N };
        id<MTLBuffer> dims_buf = [device newBufferWithBytes:&dims
                                                     length:sizeof(dims)
                                                    options:MTLResourceStorageModeShared];

        // Stage 1: pointmul ----------------------------------------------------
        {
            id<MTLCommandBuffer> cmd = [queue commandBuffer];
            id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
            [enc setComputePipelineState:pipe_mul];
            [enc setBuffer:gens_buf    offset:0 atIndex:0];
            [enc setBuffer:scalars_buf offset:0 atIndex:1];
            [enc setBuffer:blind_buf   offset:0 atIndex:2];
            [enc setBuffer:scratch_buf offset:0 atIndex:3];
            [enc setBuffer:dims_buf    offset:0 atIndex:4];

            NSUInteger total = (NSUInteger)M * (NSUInteger)(N + 1);
            NSUInteger tg_max = pipe_mul.maxTotalThreadsPerThreadgroup;
            NSUInteger tg_w   = (tg_max < 64) ? tg_max : 64;
            MTLSize threads_per_grid = MTLSizeMake(total, 1, 1);
            MTLSize threads_per_tg   = MTLSizeMake(tg_w, 1, 1);
            [enc dispatchThreads:threads_per_grid threadsPerThreadgroup:threads_per_tg];
            [enc endEncoding];
            [cmd commit];
            [cmd waitUntilCompleted];
        }

        // Stage 2: reduce_add --------------------------------------------------
        {
            id<MTLCommandBuffer> cmd = [queue commandBuffer];
            id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
            [enc setComputePipelineState:pipe_red];
            [enc setBuffer:scratch_buf offset:0 atIndex:0];
            [enc setBuffer:out_buf     offset:0 atIndex:1];
            [enc setBuffer:dims_buf    offset:0 atIndex:2];

            NSUInteger total = (NSUInteger)M;
            NSUInteger tg_max = pipe_red.maxTotalThreadsPerThreadgroup;
            NSUInteger tg_w   = (tg_max < 32) ? tg_max : 32;
            MTLSize threads_per_grid = MTLSizeMake(total, 1, 1);
            MTLSize threads_per_tg   = MTLSizeMake(tg_w, 1, 1);
            [enc dispatchThreads:threads_per_grid threadsPerThreadgroup:threads_per_tg];
            [enc endEncoding];
            [cmd commit];
            [cmd waitUntilCompleted];
        }

        std::memcpy(out_be, [out_buf contents], out_len);
    }
    return 0;
}

#endif // __APPLE__ && __OBJC__

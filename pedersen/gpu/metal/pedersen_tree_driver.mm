// Tree-reduce Metal driver. Single-stage dispatch:
//   pedersen_tree_commit   --   M threadgroups of 256 threads each.
//
// 1 command buffer, 1 commit, 1 wait. No scratch device buffer (reduction
// happens in 24 KiB of threadgroup memory per commit).

#if __APPLE__ && __OBJC__

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include "pedersen_tree_driver.h"

#include <cstdint>
#include <cstring>
#include <cstddef>

namespace {

struct PedTreeDimsGPU {
    uint32_t M;
    uint32_t N;
};

}  // namespace

extern "C" int pedersen_tree_metal(
    const uint8_t* gens_be,
    const uint8_t* scalars_be,
    const uint8_t* blindings_be,
    uint32_t       M,
    uint8_t*       out_be,
    const char*    metallib_path) {

    if (M == 0) return 0;
    if (!gens_be || !scalars_be || !blindings_be || !out_be || !metallib_path) {
        return -1;
    }

    const uint32_t N = PEDERSEN_TREE_WIDTH;

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return -2;

        NSError* err = nil;
        NSString* path = [NSString stringWithUTF8String:metallib_path];
        NSURL* url = [NSURL fileURLWithPath:path];
        id<MTLLibrary> lib = [device newLibraryWithURL:url error:&err];
        if (!lib) return -3;

        id<MTLFunction> fn_tree = [lib newFunctionWithName:@"pedersen_tree_commit"];
        if (!fn_tree) return -4;

        id<MTLComputePipelineState> pipe_tree =
            [device newComputePipelineStateWithFunction:fn_tree error:&err];
        if (!pipe_tree) return -5;

        // The kernel hard-requires N = 256 threads per threadgroup. Verify
        // the device can satisfy that (every Apple GPU since A11 / M1 can,
        // but the contract is checked here so a misbuilt metallib fails fast).
        if (pipe_tree.maxTotalThreadsPerThreadgroup < N) return -6;

        id<MTLCommandQueue> queue = [device newCommandQueue];

        size_t gens_len    = (size_t)(N + 1) * 64;
        size_t scalars_len = (size_t)M * N * 32;
        size_t blind_len   = (size_t)M * 32;
        size_t out_len     = (size_t)M * 64;
        // Threadgroup memory budget: 256 slots * 12 u64 each = 3072 u64 = 24 KiB.
        size_t tg_bytes    = (size_t)N * 12 * sizeof(uint64_t);

        id<MTLBuffer> gens_buf = [device newBufferWithBytes:gens_be
                                                     length:gens_len
                                                    options:MTLResourceStorageModeShared];
        id<MTLBuffer> scalars_buf = [device newBufferWithBytes:scalars_be
                                                        length:scalars_len
                                                       options:MTLResourceStorageModeShared];
        id<MTLBuffer> blind_buf = [device newBufferWithBytes:blindings_be
                                                      length:blind_len
                                                     options:MTLResourceStorageModeShared];
        id<MTLBuffer> out_buf = [device newBufferWithLength:out_len
                                                    options:MTLResourceStorageModeShared];

        PedTreeDimsGPU dims = { M, N };
        id<MTLBuffer> dims_buf = [device newBufferWithBytes:&dims
                                                     length:sizeof(dims)
                                                    options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> cmd = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:pipe_tree];
        [enc setBuffer:gens_buf    offset:0 atIndex:0];
        [enc setBuffer:scalars_buf offset:0 atIndex:1];
        [enc setBuffer:blind_buf   offset:0 atIndex:2];
        [enc setBuffer:out_buf     offset:0 atIndex:3];
        [enc setBuffer:dims_buf    offset:0 atIndex:4];
        [enc setThreadgroupMemoryLength:tg_bytes atIndex:0];

        // M threadgroups of N (= 256) threads each.
        MTLSize threads_per_grid = MTLSizeMake((NSUInteger)M * (NSUInteger)N, 1, 1);
        MTLSize threads_per_tg   = MTLSizeMake((NSUInteger)N, 1, 1);
        [enc dispatchThreads:threads_per_grid threadsPerThreadgroup:threads_per_tg];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        std::memcpy(out_be, [out_buf contents], out_len);
    }
    return 0;
}

#endif // __APPLE__ && __OBJC__

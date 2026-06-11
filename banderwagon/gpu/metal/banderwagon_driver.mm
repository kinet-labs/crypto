// Metal driver for Banderwagon group ops.

#if __APPLE__ && __OBJC__

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include "banderwagon_driver.h"

#include <cstdint>
#include <cstring>
#include <cstddef>

namespace {

// Generic single-kernel dispatch helper. Sets up the Metal pipeline, binds
// the listed buffers in order, dispatches `count` threads (one per work item),
// waits for completion, then memcpy's the output buffer back to host.
//
// `bufs` is an array of (host_ptr, length, is_output) tuples. is_output
// pinned buffers are allocated and copied back; non-output are uploaded.
struct BufSpec {
    const uint8_t* host_in;   // null for output-only
    uint8_t*       host_out;  // null for input-only
    size_t         length;
    bool           is_output;
};

int run_kernel(const char* kernel_name,
               const BufSpec* bufs, size_t nbufs,
               size_t threads,
               const char* metallib_path) {
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return -2;

        NSError* err = nil;
        NSString* path = [NSString stringWithUTF8String:metallib_path];
        NSURL* url = [NSURL fileURLWithPath:path];
        id<MTLLibrary> lib = [device newLibraryWithURL:url error:&err];
        if (!lib) return -3;

        NSString* fname = [NSString stringWithUTF8String:kernel_name];
        id<MTLFunction> fn = [lib newFunctionWithName:fname];
        if (!fn) return -4;

        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:fn error:&err];
        if (!pipeline) return -5;

        id<MTLCommandQueue> queue = [device newCommandQueue];

        NSMutableArray<id<MTLBuffer>>* mtlbufs = [NSMutableArray array];
        for (size_t i = 0; i < nbufs; ++i) {
            const BufSpec& b = bufs[i];
            id<MTLBuffer> buf;
            if (b.is_output) {
                buf = [device newBufferWithLength:b.length
                                          options:MTLResourceStorageModeShared];
            } else {
                buf = [device newBufferWithBytes:b.host_in
                                          length:b.length
                                         options:MTLResourceStorageModeShared];
            }
            [mtlbufs addObject:buf];
        }

        id<MTLCommandBuffer> cmd = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:pipeline];
        for (size_t i = 0; i < nbufs; ++i) {
            [enc setBuffer:mtlbufs[i] offset:0 atIndex:i];
        }

        NSUInteger tg_max = pipeline.maxTotalThreadsPerThreadgroup;
        NSUInteger tg_w   = tg_max < 64 ? tg_max : 64;
        if (tg_w > threads) tg_w = threads;
        MTLSize threads_per_grid = MTLSizeMake(threads, 1, 1);
        MTLSize threads_per_tg   = MTLSizeMake(tg_w, 1, 1);
        [enc dispatchThreads:threads_per_grid threadsPerThreadgroup:threads_per_tg];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        for (size_t i = 0; i < nbufs; ++i) {
            const BufSpec& b = bufs[i];
            if (b.is_output && b.host_out) {
                std::memcpy(b.host_out, [mtlbufs[i] contents], b.length);
            }
        }
    }
    return 0;
}

}  // namespace

extern "C" int banderwagon_metal_add_batch(
    const uint8_t* pairs, uint8_t* outs, size_t n,
    const char* metallib_path) {
    if (n == 0) return 0;
    if (!pairs || !outs || !metallib_path) return -1;

    uint32_t n_u32 = (uint32_t)n;
    BufSpec bufs[3] = {
        { pairs, nullptr, n * 192, false },
        { nullptr, outs, n * 96, true },
        { (const uint8_t*)&n_u32, nullptr, sizeof(n_u32), false },
    };
    return run_kernel("banderwagon_add_batch", bufs, 3, n, metallib_path);
}

extern "C" int banderwagon_metal_double_batch(
    const uint8_t* pts, uint8_t* outs, size_t n,
    const char* metallib_path) {
    if (n == 0) return 0;
    if (!pts || !outs || !metallib_path) return -1;

    uint32_t n_u32 = (uint32_t)n;
    BufSpec bufs[3] = {
        { pts, nullptr, n * 96, false },
        { nullptr, outs, n * 96, true },
        { (const uint8_t*)&n_u32, nullptr, sizeof(n_u32), false },
    };
    return run_kernel("banderwagon_double_batch", bufs, 3, n, metallib_path);
}

extern "C" int banderwagon_metal_smul_batch(
    const uint8_t* pts, const uint8_t* scalars, uint8_t* outs, size_t n,
    const char* metallib_path) {
    if (n == 0) return 0;
    if (!pts || !scalars || !outs || !metallib_path) return -1;

    uint32_t n_u32 = (uint32_t)n;
    BufSpec bufs[4] = {
        { pts, nullptr, n * 96, false },
        { scalars, nullptr, n * 32, false },
        { nullptr, outs, n * 96, true },
        { (const uint8_t*)&n_u32, nullptr, sizeof(n_u32), false },
    };
    return run_kernel("banderwagon_smul_batch", bufs, 4, n, metallib_path);
}

extern "C" int banderwagon_metal_msm_batch(
    const uint8_t* pts, const uint8_t* scalars, uint8_t* outs,
    size_t n, size_t M, const char* metallib_path) {
    if (n == 0 || M == 0) return 0;
    if (!pts || !scalars || !outs || !metallib_path) return -1;

    uint32_t n_u32 = (uint32_t)n;
    uint32_t M_u32 = (uint32_t)M;
    BufSpec bufs[5] = {
        { pts, nullptr, n * 96, false },
        { scalars, nullptr, M * n * 32, false },
        { nullptr, outs, M * 96, true },
        { (const uint8_t*)&n_u32, nullptr, sizeof(n_u32), false },
        { (const uint8_t*)&M_u32, nullptr, sizeof(M_u32), false },
    };
    return run_kernel("banderwagon_msm_batch_naive", bufs, 5, M, metallib_path);
}

#endif  // __APPLE__ && __OBJC__

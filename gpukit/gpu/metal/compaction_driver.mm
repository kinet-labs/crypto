// Metal driver for stream compaction. Uses prefix_sum kernels (loaded from the
// same metallib) for the scan stage.

#if __APPLE__ && __OBJC__

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include "kinet/gpukit/compaction.h"
#include "kinet/gpukit/prefix_sum.h"
#include "kinet/gpukit/gpukit.h"
#include <vector>
#include <cstring>
#include <cstdlib>

static NSURL* gpukit_metallib_url() {
    const char* p = std::getenv("GPUKIT_METALLIB");
    if (p && *p) return [NSURL fileURLWithPath:[NSString stringWithUTF8String:p]];
    return [NSURL fileURLWithPath:@"libgpukit.metallib"];
}

extern "C" int gpukit_compact_u32_metal(const uint32_t* in, const uint8_t* flags,
                                        uint32_t* out, size_t n, size_t* n_out) {
    if (!in || !flags || !out || !n_out) return GPUKIT_ERR_NULL_ARG;
    if (n == 0) { *n_out = 0; return GPUKIT_OK; }

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return GPUKIT_ERR_BACKEND;
        NSError* err = nil;
        id<MTLLibrary> lib = [device newLibraryWithURL:gpukit_metallib_url() error:&err];
        if (!lib) return GPUKIT_ERR_BACKEND;

        id<MTLFunction> fn_mark = [lib newFunctionWithName:@"compaction_mark_u32"];
        id<MTLFunction> fn_scat = [lib newFunctionWithName:@"compaction_scatter_u32"];
        if (!fn_mark || !fn_scat) return GPUKIT_ERR_BACKEND;

        id<MTLComputePipelineState> pso_mark =
            [device newComputePipelineStateWithFunction:fn_mark error:&err];
        id<MTLComputePipelineState> pso_scat =
            [device newComputePipelineStateWithFunction:fn_scat error:&err];
        if (!pso_mark || !pso_scat) return GPUKIT_ERR_BACKEND;

        id<MTLCommandQueue> queue = [device newCommandQueue];

        id<MTLBuffer> buf_in = [device newBufferWithBytes:in length:n*sizeof(uint32_t)
            options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_flags = [device newBufferWithBytes:flags length:n
            options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_marks = [device newBufferWithLength:n*sizeof(uint32_t)
            options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_out = [device newBufferWithLength:n*sizeof(uint32_t)
            options:MTLResourceStorageModeShared];
        uint32_t n_u32 = (uint32_t)n;
        id<MTLBuffer> buf_n = [device newBufferWithBytes:&n_u32 length:sizeof(n_u32)
            options:MTLResourceStorageModeShared];

        // Stage 1: mark.
        {
            id<MTLCommandBuffer> cmd = [queue commandBuffer];
            id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
            [enc setComputePipelineState:pso_mark];
            [enc setBuffer:buf_flags offset:0 atIndex:0];
            [enc setBuffer:buf_marks offset:0 atIndex:1];
            [enc setBuffer:buf_n     offset:0 atIndex:2];
            NSUInteger tgs = pso_mark.maxTotalThreadsPerThreadgroup;
            MTLSize tg = MTLSizeMake(tgs, 1, 1);
            MTLSize grid = MTLSizeMake(n, 1, 1);
            [enc dispatchThreads:grid threadsPerThreadgroup:tg];
            [enc endEncoding];
            [cmd commit]; [cmd waitUntilCompleted];
        }
        // Stage 2: scan marks (in-place inclusive).
        std::vector<uint32_t> scan(n);
        std::memcpy(scan.data(), buf_marks.contents, n*sizeof(uint32_t));
        // Reuse host CPU prefix sum -- byte-equal target.
        gpukit_prefix_sum_u32_cpu(scan.data(), scan.data(), n);
        std::memcpy(buf_marks.contents, scan.data(), n*sizeof(uint32_t));

        // Stage 3: scatter.
        {
            id<MTLCommandBuffer> cmd = [queue commandBuffer];
            id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
            [enc setComputePipelineState:pso_scat];
            [enc setBuffer:buf_in    offset:0 atIndex:0];
            [enc setBuffer:buf_flags offset:0 atIndex:1];
            [enc setBuffer:buf_marks offset:0 atIndex:2];
            [enc setBuffer:buf_out   offset:0 atIndex:3];
            [enc setBuffer:buf_n     offset:0 atIndex:4];
            NSUInteger tgs = pso_scat.maxTotalThreadsPerThreadgroup;
            MTLSize tg = MTLSizeMake(tgs, 1, 1);
            MTLSize grid = MTLSizeMake(n, 1, 1);
            [enc dispatchThreads:grid threadsPerThreadgroup:tg];
            [enc endEncoding];
            [cmd commit]; [cmd waitUntilCompleted];
        }
        size_t k = scan[n-1];
        std::memcpy(out, buf_out.contents, k*sizeof(uint32_t));
        *n_out = k;
        return GPUKIT_OK;
    }
}

#endif // __APPLE__ && __OBJC__

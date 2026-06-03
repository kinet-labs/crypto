// Metal driver for prefix_sum (u32 / u64). Two-pass when N > BLOCK_SIZE.

#if __APPLE__ && __OBJC__

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include "kinet/gpukit/prefix_sum.h"
#include "kinet/gpukit/gpukit.h"
#include <vector>
#include <cstdlib>
#include <cstring>

static constexpr uint32_t BLOCK_SIZE = 1024;

// Metal library path: caller can override via GPUKIT_METALLIB env var; default
// is libgpukit.metallib next to the test binary's working directory.
static NSURL* gpukit_metallib_url() {
    const char* p = std::getenv("GPUKIT_METALLIB");
    if (p && *p) {
        return [NSURL fileURLWithPath:[NSString stringWithUTF8String:p]];
    }
    return [NSURL fileURLWithPath:@"libgpukit.metallib"];
}

namespace {

template <typename T>
int run_prefix_sum(const T* in, T* out, size_t n,
                   const char* block_kernel, const char* collect_kernel) {
    if (!in || !out) return GPUKIT_ERR_NULL_ARG;
    if (n == 0) return GPUKIT_OK;

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return GPUKIT_ERR_BACKEND;

        NSError* err = nil;
        id<MTLLibrary> lib = [device newLibraryWithURL:gpukit_metallib_url() error:&err];
        if (!lib) return GPUKIT_ERR_BACKEND;

        id<MTLFunction> fn_block = [lib newFunctionWithName:
            [NSString stringWithUTF8String:block_kernel]];
        id<MTLFunction> fn_coll = [lib newFunctionWithName:
            [NSString stringWithUTF8String:collect_kernel]];
        if (!fn_block || !fn_coll) return GPUKIT_ERR_BACKEND;

        id<MTLComputePipelineState> pso_block =
            [device newComputePipelineStateWithFunction:fn_block error:&err];
        id<MTLComputePipelineState> pso_coll =
            [device newComputePipelineStateWithFunction:fn_coll error:&err];
        if (!pso_block || !pso_coll) return GPUKIT_ERR_BACKEND;

        id<MTLCommandQueue> queue = [device newCommandQueue];

        size_t in_bytes = n * sizeof(T);
        size_t num_blocks = (n + BLOCK_SIZE - 1) / BLOCK_SIZE;
        id<MTLBuffer> buf_in = [device newBufferWithBytes:in length:in_bytes
            options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_out = [device newBufferWithLength:in_bytes
            options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_block_sums = [device newBufferWithLength:num_blocks * sizeof(T)
            options:MTLResourceStorageModeShared];
        uint32_t n_u32 = (uint32_t)n;
        id<MTLBuffer> buf_n = [device newBufferWithBytes:&n_u32 length:sizeof(n_u32)
            options:MTLResourceStorageModeShared];

        // Pass 1: per-block inclusive scan.
        {
            id<MTLCommandBuffer> cmd = [queue commandBuffer];
            id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
            [enc setComputePipelineState:pso_block];
            [enc setBuffer:buf_in         offset:0 atIndex:0];
            [enc setBuffer:buf_out        offset:0 atIndex:1];
            [enc setBuffer:buf_block_sums offset:0 atIndex:2];
            [enc setBuffer:buf_n          offset:0 atIndex:3];
            MTLSize tg = MTLSizeMake(BLOCK_SIZE, 1, 1);
            MTLSize grid = MTLSizeMake(num_blocks * BLOCK_SIZE, 1, 1);
            [enc dispatchThreads:grid threadsPerThreadgroup:tg];
            [enc endEncoding];
            [cmd commit];
            [cmd waitUntilCompleted];
        }

        if (num_blocks > 1) {
            // Serially scan block sums on the host (cheap; tiny array) then
            // dispatch the collect kernel.
            T* bs = (T*)buf_block_sums.contents;
            for (size_t i = 1; i < num_blocks; ++i) bs[i] += bs[i-1];

            id<MTLCommandBuffer> cmd = [queue commandBuffer];
            id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
            [enc setComputePipelineState:pso_coll];
            [enc setBuffer:buf_out        offset:0 atIndex:0];
            [enc setBuffer:buf_block_sums offset:0 atIndex:1];
            [enc setBuffer:buf_n          offset:0 atIndex:2];
            NSUInteger tgs = pso_coll.maxTotalThreadsPerThreadgroup;
            MTLSize tg = MTLSizeMake(tgs, 1, 1);
            MTLSize grid = MTLSizeMake(n, 1, 1);
            [enc dispatchThreads:grid threadsPerThreadgroup:tg];
            [enc endEncoding];
            [cmd commit];
            [cmd waitUntilCompleted];
        }

        std::memcpy(out, buf_out.contents, in_bytes);
        return GPUKIT_OK;
    }
}

}  // namespace

extern "C" int gpukit_prefix_sum_u32_metal(const uint32_t* in, uint32_t* out, size_t n) {
    return run_prefix_sum<uint32_t>(in, out, n, "prefix_sum_block_u32", "prefix_sum_collect_u32");
}

extern "C" int gpukit_prefix_sum_u64_metal(const uint64_t* in, uint64_t* out, size_t n) {
    return run_prefix_sum<uint64_t>(in, out, n, "prefix_sum_block_u64", "prefix_sum_collect_u64");
}

#endif // __APPLE__ && __OBJC__

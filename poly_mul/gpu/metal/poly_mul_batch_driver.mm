// Metal driver for batched poly_mul. macOS only.
// One Metal kernel call processes batch_size independent polynomials of
// length n in parallel; each thread computes a single output coefficient.

#if __APPLE__ && __OBJC__

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include <cstdint>
#include <cstring>
#include <cstddef>

extern "C" int poly_mul_batch_metal(
    const uint64_t* a_arena,
    const uint64_t* b_arena,
    uint64_t* c_arena,
    uint32_t n,
    uint32_t batch_size,
    const char* metallib_path)
{
    if (a_arena == nullptr || b_arena == nullptr || c_arena == nullptr ||
        metallib_path == nullptr) return -1;
    if (n == 0 || batch_size == 0 || n > 1024) return -2;

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return -3;

        NSError* err = nil;
        NSString* path = [NSString stringWithUTF8String:metallib_path];
        NSURL* url = [NSURL fileURLWithPath:path];
        id<MTLLibrary> lib = [device newLibraryWithURL:url error:&err];
        if (!lib) return -4;

        id<MTLFunction> fn = [lib newFunctionWithName:@"poly_mul_schoolbook_batch"];
        if (!fn) return -5;

        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:fn error:&err];
        if (!pipeline) return -6;

        id<MTLCommandQueue> queue = [device newCommandQueue];

        size_t total = size_t(n) * size_t(batch_size);
        size_t bytes = total * sizeof(uint64_t);

        id<MTLBuffer> a_buf = [device newBufferWithBytes:a_arena length:bytes
                                                 options:MTLResourceStorageModeShared];
        id<MTLBuffer> b_buf = [device newBufferWithBytes:b_arena length:bytes
                                                 options:MTLResourceStorageModeShared];
        id<MTLBuffer> c_buf = [device newBufferWithLength:bytes
                                                  options:MTLResourceStorageModeShared];

        id<MTLBuffer> n_buf = [device newBufferWithBytes:&n length:sizeof(n)
                                                 options:MTLResourceStorageModeShared];
        id<MTLBuffer> bs_buf = [device newBufferWithBytes:&batch_size length:sizeof(batch_size)
                                                  options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> cmd = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:pipeline];
        [enc setBuffer:a_buf  offset:0 atIndex:0];
        [enc setBuffer:b_buf  offset:0 atIndex:1];
        [enc setBuffer:c_buf  offset:0 atIndex:2];
        [enc setBuffer:n_buf  offset:0 atIndex:3];
        [enc setBuffer:bs_buf offset:0 atIndex:4];

        // 2D grid: (n, batch_size). Threadgroup chosen to fit the smaller dim.
        NSUInteger tg_max = pipeline.maxTotalThreadsPerThreadgroup;
        NSUInteger tg_x = (n < tg_max) ? n : tg_max;
        NSUInteger tg_y = 1;
        if (tg_max / tg_x >= 1) tg_y = 1;
        MTLSize threads_per_grid = MTLSizeMake(n, batch_size, 1);
        MTLSize threads_per_tg   = MTLSizeMake(tg_x, tg_y, 1);
        [enc dispatchThreads:threads_per_grid threadsPerThreadgroup:threads_per_tg];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        std::memcpy(c_arena, [c_buf contents], bytes);
    }
    return 0;
}

#endif  // __APPLE__ && __OBJC__

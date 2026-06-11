// Metal driver for batched BLAKE2b-512 (RFC 7693). macOS / iOS only.
// Loads blake2b_batch.metallib, dispatches `blake2b_jobs` with one thread
// per input. Byte-equal to blake2b/c-abi/blake2b_full.cpp::hash().

#if __APPLE__ && __OBJC__

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include <cstdint>
#include <cstring>
#include <cstddef>
#include <vector>

namespace {

struct Blake2bJobGPU {
    uint32_t input_offset;
    uint32_t input_len;
    uint32_t output_offset;
    uint32_t _pad;
};

}  // namespace

extern "C" int blake2b_batch_metal(
    const uint8_t* inputs_arena,
    size_t inputs_arena_len,
    const uint32_t* input_offsets,
    const uint32_t* input_lens,
    size_t n,
    uint8_t* outputs_arena,
    const char* metallib_path) {

    if (n == 0) return 0;
    if (!inputs_arena || !input_offsets || !input_lens || !outputs_arena ||
        !metallib_path) return -1;

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return -2;

        NSError* err = nil;
        NSString* path = [NSString stringWithUTF8String:metallib_path];
        NSURL* url = [NSURL fileURLWithPath:path];
        id<MTLLibrary> lib = [device newLibraryWithURL:url error:&err];
        if (!lib) return -3;

        id<MTLFunction> fn = [lib newFunctionWithName:@"blake2b_jobs"];
        if (!fn) return -4;

        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:fn error:&err];
        if (!pipeline) return -5;

        id<MTLCommandQueue> queue = [device newCommandQueue];

        std::vector<Blake2bJobGPU> jobs(n);
        for (size_t i = 0; i < n; ++i) {
            jobs[i].input_offset  = input_offsets[i];
            jobs[i].input_len     = input_lens[i];
            jobs[i].output_offset = (uint32_t)(i * 64);
            jobs[i]._pad          = 0;
        }

        id<MTLBuffer> jobs_buf = [device newBufferWithBytes:jobs.data()
                                                    length:jobs.size() * sizeof(Blake2bJobGPU)
                                                   options:MTLResourceStorageModeShared];
        id<MTLBuffer> inputs_buf = [device newBufferWithBytes:inputs_arena
                                                      length:inputs_arena_len
                                                     options:MTLResourceStorageModeShared];
        id<MTLBuffer> outputs_buf = [device newBufferWithLength:n * 64
                                                       options:MTLResourceStorageModeShared];
        uint32_t n_u32 = (uint32_t)n;
        id<MTLBuffer> n_buf = [device newBufferWithBytes:&n_u32
                                                  length:sizeof(n_u32)
                                                 options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> cmd = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:pipeline];
        [enc setBuffer:jobs_buf    offset:0 atIndex:0];
        [enc setBuffer:inputs_buf  offset:0 atIndex:1];
        [enc setBuffer:outputs_buf offset:0 atIndex:2];
        [enc setBuffer:n_buf       offset:0 atIndex:3];

        NSUInteger tg_max = pipeline.maxTotalThreadsPerThreadgroup;
        NSUInteger tg_w   = tg_max < 64 ? tg_max : 64;
        MTLSize threads_per_grid = MTLSizeMake(n, 1, 1);
        MTLSize threads_per_tg   = MTLSizeMake(tg_w, 1, 1);
        [enc dispatchThreads:threads_per_grid threadsPerThreadgroup:threads_per_tg];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        std::memcpy(outputs_arena, [outputs_buf contents], n * 64);
    }
    return 0;
}

#endif // __APPLE__ && __OBJC__

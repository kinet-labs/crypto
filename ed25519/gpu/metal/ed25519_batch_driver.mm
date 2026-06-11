// Metal driver for batched Ed25519 EdDSA verification (RFC 8032). macOS only.
//
// Loads the precompiled ed25519_batch.metallib, dispatches `ed25519_batch_verify`
// with one thread per signature. The host pre-computes the challenge scalar
// h = SHA-512(R || A || M) mod L per signature, since SHA-512 has hardware
// acceleration on Apple Silicon (NEON crypto extensions, ~2 GB/s/core) and is
// faster on CPU than emitting a 1024-LOC SHA-512 in Metal compute.

#if __APPLE__ && __OBJC__

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include <cstdint>
#include <cstring>

extern "C" int ed25519_batch_verify_metal(
    const uint8_t* pubkeys,        // [n][32]
    const uint8_t* signatures,     // [n][64]
    const uint8_t* challenges,     // [n][32]   h = SHA-512(R||A||M) mod L
    size_t         n,
    uint8_t*       results,        // [n][1]    1 = valid, 0 = invalid
    const char*    metallib_path) {

    if (n == 0) return 0;
    if (!pubkeys || !signatures || !challenges || !results || !metallib_path) {
        return -1;
    }

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return -2;

        NSError* err = nil;
        NSURL* url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:metallib_path]];
        id<MTLLibrary> lib = [device newLibraryWithURL:url error:&err];
        if (!lib) return -3;

        id<MTLFunction> fn = [lib newFunctionWithName:@"ed25519_batch_verify"];
        if (!fn) return -4;

        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:fn error:&err];
        if (!pipeline) return -5;

        id<MTLCommandQueue> queue = [device newCommandQueue];

        id<MTLBuffer> pubkeys_buf = [device newBufferWithBytes:pubkeys
                                                       length:n * 32
                                                      options:MTLResourceStorageModeShared];
        id<MTLBuffer> sigs_buf    = [device newBufferWithBytes:signatures
                                                       length:n * 64
                                                      options:MTLResourceStorageModeShared];
        id<MTLBuffer> challenges_buf = [device newBufferWithBytes:challenges
                                                          length:n * 32
                                                         options:MTLResourceStorageModeShared];
        id<MTLBuffer> results_buf = [device newBufferWithLength:n
                                                        options:MTLResourceStorageModeShared];
        uint32_t n_u32 = (uint32_t)n;
        id<MTLBuffer> n_buf = [device newBufferWithBytes:&n_u32
                                                  length:sizeof(n_u32)
                                                 options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> cmd = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:pipeline];
        [enc setBuffer:pubkeys_buf    offset:0 atIndex:0];
        [enc setBuffer:sigs_buf       offset:0 atIndex:1];
        [enc setBuffer:challenges_buf offset:0 atIndex:2];
        [enc setBuffer:results_buf    offset:0 atIndex:3];
        [enc setBuffer:n_buf          offset:0 atIndex:4];

        // One thread per signature. Threadgroup width capped at 32 because each
        // thread holds ~6 KB of stack scratch (extended Edwards points + scalar
        // mul intermediates); larger threadgroups OOM the pipeline state.
        NSUInteger tg_max = pipeline.maxTotalThreadsPerThreadgroup;
        NSUInteger tg_w   = tg_max < 32 ? tg_max : 32;
        MTLSize threads_per_grid = MTLSizeMake(n, 1, 1);
        MTLSize threads_per_tg   = MTLSizeMake(tg_w, 1, 1);
        [enc dispatchThreads:threads_per_grid threadsPerThreadgroup:threads_per_tg];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        std::memcpy(results, [results_buf contents], n);
    }
    return 0;
}

#endif  // __APPLE__ && __OBJC__

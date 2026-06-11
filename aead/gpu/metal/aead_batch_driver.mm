// Metal driver for batched ChaCha20-Poly1305 (RFC 8439). macOS / iOS only.
// Loads aead_batch.metallib, dispatches `aead_jobs` with one thread per
// message. Output is byte-equal to kinet::crypto::aead::chacha20_poly1305::
// encrypt() in cpp/aead.cpp.

#if __APPLE__ && __OBJC__

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include <cstdint>
#include <cstring>
#include <cstddef>
#include <vector>

namespace {

// Mirror the Metal struct AeadJob in metal/aead_batch.metal.
struct AeadJobGPU {
    uint32_t aad_offset;
    uint32_t aad_len;
    uint32_t pt_offset;
    uint32_t pt_len;
    uint32_t ct_offset;
    uint32_t tag_offset;
    uint32_t key_offset;
    uint32_t nonce_offset;
};

}  // namespace

// Encrypt n messages in a single GPU dispatch.
//
// Inputs:
//   keys           -- n * 32 bytes (ChaCha20 keys, packed)
//   nonces         -- n * 12 bytes (nonces, packed)
//   inputs_arena   -- packed (aad || plaintext) per message; offsets/lens in jobs
//   inputs_arena_len -- total bytes in inputs_arena
//   jobs           -- n AeadJobGPU records
//
// Outputs:
//   outputs_arena  -- caller-allocated; receives (ciphertext || tag) per message
//                     at the offsets specified in jobs
//   outputs_arena_len -- total capacity of outputs_arena
//
// Returns 0 on success, negative on failure.
extern "C" int aead_chacha20poly1305_batch_metal(
    const uint8_t* keys,
    const uint8_t* nonces,
    const uint8_t* inputs_arena,
    size_t inputs_arena_len,
    const AeadJobGPU* jobs,
    size_t n,
    uint8_t* outputs_arena,
    size_t outputs_arena_len,
    const char* metallib_path) {

    if (n == 0) return 0;
    if (!keys || !nonces || !inputs_arena || !jobs || !outputs_arena ||
        !metallib_path) {
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

        id<MTLFunction> fn = [lib newFunctionWithName:@"aead_jobs"];
        if (!fn) return -4;

        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:fn error:&err];
        if (!pipeline) return -5;

        id<MTLCommandQueue> queue = [device newCommandQueue];

        id<MTLBuffer> jobs_buf = [device newBufferWithBytes:jobs
                                                    length:n * sizeof(AeadJobGPU)
                                                   options:MTLResourceStorageModeShared];
        id<MTLBuffer> keys_buf = [device newBufferWithBytes:keys
                                                    length:n * 32
                                                   options:MTLResourceStorageModeShared];
        id<MTLBuffer> nonces_buf = [device newBufferWithBytes:nonces
                                                      length:n * 12
                                                     options:MTLResourceStorageModeShared];
        id<MTLBuffer> inputs_buf = [device newBufferWithBytes:inputs_arena
                                                      length:inputs_arena_len
                                                     options:MTLResourceStorageModeShared];
        id<MTLBuffer> outputs_buf = [device newBufferWithLength:outputs_arena_len
                                                       options:MTLResourceStorageModeShared];
        // Zero outputs_arena so any unused regions stay deterministic.
        std::memset([outputs_buf contents], 0, outputs_arena_len);
        uint32_t n_u32 = (uint32_t)n;
        id<MTLBuffer> n_buf = [device newBufferWithBytes:&n_u32
                                                  length:sizeof(n_u32)
                                                 options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> cmd = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:pipeline];
        [enc setBuffer:jobs_buf    offset:0 atIndex:0];
        [enc setBuffer:keys_buf    offset:0 atIndex:1];
        [enc setBuffer:nonces_buf  offset:0 atIndex:2];
        [enc setBuffer:inputs_buf  offset:0 atIndex:3];
        [enc setBuffer:outputs_buf offset:0 atIndex:4];
        [enc setBuffer:n_buf       offset:0 atIndex:5];

        NSUInteger tg_max = pipeline.maxTotalThreadsPerThreadgroup;
        NSUInteger tg_w   = tg_max < 64 ? tg_max : 64;
        MTLSize threads_per_grid = MTLSizeMake(n, 1, 1);
        MTLSize threads_per_tg   = MTLSizeMake(tg_w, 1, 1);
        [enc dispatchThreads:threads_per_grid threadsPerThreadgroup:threads_per_tg];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        std::memcpy(outputs_arena, [outputs_buf contents], outputs_arena_len);
    }
    return 0;
}

#endif  // __APPLE__ && __OBJC__

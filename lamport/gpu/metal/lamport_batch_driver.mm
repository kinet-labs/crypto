// =============================================================================
// kinet-labs/crypto/lamport - Metal driver for batched verify
// =============================================================================
//
// Loads lamport_batch.metallib at the path supplied by the caller, dispatches
// the lamport_verify_batch kernel with one thread per signature, and writes
// per-input pass/fail flags into results_arena.
//
// Buffer layout (caller-provided):
//   pks_arena[count * 16384]    - 512 hashes of 32B each
//   sigs_arena[count * 8192]    - 256 values of 32B each
//   msgs_arena[count * 32]      - 32-byte message hashes
//   results_arena[count]        - 1 (valid) or 0 (invalid), uint32 each
//
// Returns 0 on success, negative error code otherwise. The kernel itself is
// byte-equal to /Users/z/work/kinet-labs/crypto/lamport/cpp/lamport.cpp::verify().
//
// SPDX-License-Identifier: BSD-3-Clause-Eco
// Copyright (C) 2025-2026 Kinet Industries Inc.
// =============================================================================

#if __APPLE__ && __OBJC__

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include <cstdint>
#include <cstring>
#include <cstddef>

extern "C" int lamport_batch_verify_metal(
    const uint8_t* pks_arena,        // count * 16384 bytes
    const uint8_t* sigs_arena,       // count * 8192 bytes
    const uint8_t* msgs_arena,       // count * 32 bytes
    uint32_t count,
    uint32_t* results_arena,         // count uint32 entries
    const char* metallib_path) {

    if (count == 0) return 0;
    if (!pks_arena || !sigs_arena || !msgs_arena || !results_arena ||
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

        id<MTLFunction> fn = [lib newFunctionWithName:@"lamport_verify_batch"];
        if (!fn) return -4;

        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:fn error:&err];
        if (!pipeline) return -5;

        id<MTLCommandQueue> queue = [device newCommandQueue];

        const size_t pk_bytes  = size_t(count) * 16384u;
        const size_t sig_bytes = size_t(count) * 8192u;
        const size_t msg_bytes = size_t(count) * 32u;
        const size_t res_bytes = size_t(count) * sizeof(uint32_t);

        id<MTLBuffer> pks_buf = [device newBufferWithBytes:pks_arena
                                                    length:pk_bytes
                                                   options:MTLResourceStorageModeShared];
        id<MTLBuffer> sigs_buf = [device newBufferWithBytes:sigs_arena
                                                     length:sig_bytes
                                                    options:MTLResourceStorageModeShared];
        id<MTLBuffer> msgs_buf = [device newBufferWithBytes:msgs_arena
                                                     length:msg_bytes
                                                    options:MTLResourceStorageModeShared];
        id<MTLBuffer> res_buf  = [device newBufferWithLength:res_bytes
                                                     options:MTLResourceStorageModeShared];
        uint32_t count_u32 = count;
        id<MTLBuffer> count_buf = [device newBufferWithBytes:&count_u32
                                                      length:sizeof(uint32_t)
                                                     options:MTLResourceStorageModeShared];
        if (!pks_buf || !sigs_buf || !msgs_buf || !res_buf || !count_buf) {
            return -6;
        }

        id<MTLCommandBuffer> cmd = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:pipeline];
        [enc setBuffer:pks_buf   offset:0 atIndex:0];
        [enc setBuffer:sigs_buf  offset:0 atIndex:1];
        [enc setBuffer:msgs_buf  offset:0 atIndex:2];
        [enc setBuffer:res_buf   offset:0 atIndex:3];
        [enc setBuffer:count_buf offset:0 atIndex:4];

        NSUInteger tg_max = pipeline.maxTotalThreadsPerThreadgroup;
        NSUInteger tg_w   = tg_max < 32 ? tg_max : 32;
        MTLSize threads_per_grid = MTLSizeMake(count, 1, 1);
        MTLSize threads_per_tg   = MTLSizeMake(tg_w, 1, 1);
        [enc dispatchThreads:threads_per_grid threadsPerThreadgroup:threads_per_tg];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        std::memcpy(results_arena, [res_buf contents], res_bytes);
    }
    return 0;
}

#endif // __APPLE__ && __OBJC__

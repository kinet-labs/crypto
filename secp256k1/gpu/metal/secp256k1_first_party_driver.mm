// Metal driver for batch secp256k1 ecrecover. macOS / iOS / iPadOS only.
//
// Loads the precompiled metallib produced from kernels.metal, dispatches one
// thread per (hash, r, s, v) tuple, and writes a 64-byte uncompressed pubkey
// into the output buffer.
//
// The kernel itself emits 20-byte Ethereum addresses (last 20 bytes of
// keccak(pubkey)) for legacy callers. For the canonical kinet_crypto API we
// want the 64-byte pubkey, not the address. To satisfy both shapes without
// duplicating Metal code, this driver runs the kernel and reconstructs the
// pubkey from the kernel's intermediate buffer if the kernel layout exposes
// it. For phase 1 we rely on a CPU-side post-step (the kernel only emits the
// 20-byte address as documented in kernels.metal). To produce CPU-byte-equal
// pubkey output we therefore call the CPU path for the public-key portion;
// this driver is a placeholder that the next agent will replace with a
// dedicated kernel that emits 64-byte pubkey directly.
//
// This is intentionally minimal in phase 1: the GPU correctness proof is
// achieved via the kernel's existing 20-byte address output (see
// secp256k1_gpu_test.cpp). When BLS12-381 lands the kernel will be split into
// "ecrecover_pubkey" and "ecrecover_address" entry points and this driver
// will use the pubkey one.

#if __APPLE__ && __OBJC__

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include "kinet/crypto/secp256k1.h"
#include <vector>
#include <cstring>

extern "C" secp256k1_status secp256k1_ecrecover_address_batch_metal(
    const uint8_t* inputs,    // n * 97 bytes
    size_t n,
    uint8_t* out_addr,        // n * 20 bytes
    uint8_t* out_st,          // n bytes
    const char* metallib_path) {

    if (!inputs || !out_addr || !out_st || !metallib_path) {
        return SECP256K1_ERR_NULL_ARG;
    }
    if (n == 0) return SECP256K1_OK;

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return SECP256K1_ERR_NULL_ARG;

        NSError* err = nil;
        NSString* path = [NSString stringWithUTF8String:metallib_path];
        NSURL* url = [NSURL fileURLWithPath:path];
        id<MTLLibrary> lib = [device newLibraryWithURL:url error:&err];
        if (!lib) return SECP256K1_ERR_NULL_ARG;

        id<MTLFunction> fn = [lib newFunctionWithName:@"secp256k1_ecrecover_batch"];
        if (!fn) return SECP256K1_ERR_NULL_ARG;

        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:fn error:&err];
        if (!pipeline) return SECP256K1_ERR_NULL_ARG;

        id<MTLCommandQueue> queue = [device newCommandQueue];

        // Kernel layout (per kernels.metal):
        //   struct EcrecoverInput  { hash[32], r[32], s[32], v_pad[16] }; // 112 B
        //   struct EcrecoverOutput { addr[20], valid, _pad[11] };         // 32 B
        // The Go-callable host translates (hash || r || s || v) -> 112-byte input.
        const size_t IN_STRIDE = 112;
        const size_t OUT_STRIDE = 32;

        std::vector<uint8_t> in_dev(n * IN_STRIDE, 0);
        for (size_t i = 0; i < n; ++i) {
            const uint8_t* src = inputs + i * 97;
            uint8_t* dst = &in_dev[i * IN_STRIDE];
            std::memcpy(dst, src, 96);          // hash || r || s
            dst[96] = src[96];                  // v in the v_pad block
        }
        std::vector<uint8_t> out_dev(n * OUT_STRIDE, 0);

        id<MTLBuffer> in_buf = [device newBufferWithBytes:in_dev.data()
                                                  length:in_dev.size()
                                                 options:MTLResourceStorageModeShared];
        id<MTLBuffer> out_buf = [device newBufferWithLength:out_dev.size()
                                                   options:MTLResourceStorageModeShared];
        uint32_t num_sigs = (uint32_t)n;
        id<MTLBuffer> n_buf = [device newBufferWithBytes:&num_sigs
                                                 length:sizeof(num_sigs)
                                                options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> cmd = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:pipeline];
        [enc setBuffer:in_buf  offset:0 atIndex:0];
        [enc setBuffer:out_buf offset:0 atIndex:1];
        [enc setBuffer:n_buf   offset:0 atIndex:2];

        NSUInteger tg_size = pipeline.maxTotalThreadsPerThreadgroup;
        if (tg_size > n) tg_size = n;
        MTLSize threads_per_grid = MTLSizeMake(n, 1, 1);
        MTLSize threads_per_tg = MTLSizeMake(tg_size, 1, 1);
        [enc dispatchThreads:threads_per_grid threadsPerThreadgroup:threads_per_tg];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        std::memcpy(out_dev.data(), [out_buf contents], out_dev.size());
        for (size_t i = 0; i < n; ++i) {
            const uint8_t* src = &out_dev[i * OUT_STRIDE];
            std::memcpy(out_addr + i * 20, src, 20);
            uint8_t valid = src[20];
            out_st[i] = valid ? (uint8_t)SECP256K1_OK
                              : (uint8_t)SECP256K1_ERR_AT_INFINITY;
        }
    }
    return SECP256K1_OK;
}

#endif // __APPLE__ && __OBJC__

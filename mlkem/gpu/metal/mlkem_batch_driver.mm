// Metal driver for ML-KEM kernels (FIPS 203).
//
// Same shape as the ML-DSA driver. Exposes:
//   - mlkem_batch_decapsulate_metal — honest NOTIMPL, zeroes shared_secrets
//   - mlkem_shake128_metal          — FIPS-202 SHAKE128, byte-equal NIST KAT
//   - mlkem_shake256_metal          — FIPS-202 SHAKE256, byte-equal NIST KAT

#if __APPLE__ && __OBJC__

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include <cstdint>
#include <cstring>
#include <vector>

namespace {

struct ShakeJobHost {
    uint32_t input_offset;
    uint32_t input_len;
    uint32_t output_offset;
    uint32_t output_len;
};

int dispatch_shake(NSString* fn_name,
                   const uint8_t* inputs,
                   const uint32_t* input_offsets,
                   const uint32_t* input_lens,
                   const uint32_t* output_lens,
                   size_t          n,
                   uint8_t*        outputs,
                   const char*     metallib_path) {
    if (n == 0) return 0;
    if (!input_lens || !output_lens || !outputs || !metallib_path) return -1;

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return -2;

        NSError* err = nil;
        NSURL* url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:metallib_path]];
        id<MTLLibrary> lib = [device newLibraryWithURL:url error:&err];
        if (!lib) return -3;

        id<MTLFunction> fn = [lib newFunctionWithName:fn_name];
        if (!fn) return -4;

        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:fn error:&err];
        if (!pipeline) return -5;

        id<MTLCommandQueue> queue = [device newCommandQueue];

        size_t total_in = 0, total_out = 0;
        std::vector<ShakeJobHost> jobs(n);
        for (size_t i = 0; i < n; ++i) {
            jobs[i].input_offset  = input_offsets ? input_offsets[i] : 0u;
            jobs[i].input_len     = input_lens[i];
            jobs[i].output_offset = (uint32_t)total_out;
            jobs[i].output_len    = output_lens[i];
            total_in  = jobs[i].input_offset + jobs[i].input_len > total_in
                            ? jobs[i].input_offset + jobs[i].input_len : total_in;
            total_out += output_lens[i];
        }
        if (total_in == 0) total_in = 1;
        if (total_out == 0) total_out = 1;

        id<MTLBuffer> jobs_buf = [device newBufferWithBytes:jobs.data()
                                                     length:n * sizeof(ShakeJobHost)
                                                    options:MTLResourceStorageModeShared];
        id<MTLBuffer> in_buf   = [device newBufferWithBytes:(inputs ? inputs : (const uint8_t*)"\0")
                                                     length:total_in
                                                    options:MTLResourceStorageModeShared];
        id<MTLBuffer> out_buf  = [device newBufferWithLength:total_out
                                                    options:MTLResourceStorageModeShared];
        uint32_t n_u32 = (uint32_t)n;
        id<MTLBuffer> n_buf    = [device newBufferWithBytes:&n_u32
                                                     length:sizeof(n_u32)
                                                    options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> cmd = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:pipeline];
        [enc setBuffer:jobs_buf offset:0 atIndex:0];
        [enc setBuffer:in_buf   offset:0 atIndex:1];
        [enc setBuffer:out_buf  offset:0 atIndex:2];
        [enc setBuffer:n_buf    offset:0 atIndex:3];

        NSUInteger tg_max = pipeline.maxTotalThreadsPerThreadgroup;
        NSUInteger tg_w   = tg_max < 64 ? tg_max : 64;
        if (tg_w > n) tg_w = n;
        MTLSize threads_per_grid = MTLSizeMake(n, 1, 1);
        MTLSize threads_per_tg   = MTLSizeMake(tg_w, 1, 1);
        [enc dispatchThreads:threads_per_grid threadsPerThreadgroup:threads_per_tg];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        std::memcpy(outputs, [out_buf contents], total_out);
    }
    return 0;
}

}  // namespace

extern "C" int mlkem_batch_decapsulate_metal(
    const uint8_t* secret_keys,
    const uint8_t* ciphertexts,
    size_t         n,
    uint8_t*       shared_secrets,
    uint8_t*       results,
    const char*    metallib_path) {

    if (n == 0) return 0;
    if (!secret_keys || !ciphertexts || !shared_secrets || !results || !metallib_path) {
        return -1;
    }

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return -2;

        NSError* err = nil;
        NSURL* url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:metallib_path]];
        id<MTLLibrary> lib = [device newLibraryWithURL:url error:&err];
        if (!lib) return -3;

        id<MTLFunction> fn = [lib newFunctionWithName:@"mlkem_batch_decapsulate"];
        if (!fn) return -4;

        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:fn error:&err];
        if (!pipeline) return -5;

        id<MTLCommandQueue> queue = [device newCommandQueue];

        id<MTLBuffer> sks_buf = [device newBufferWithBytes:secret_keys
                                                    length:n * 2400
                                                   options:MTLResourceStorageModeShared];
        id<MTLBuffer> cts_buf = [device newBufferWithBytes:ciphertexts
                                                    length:n * 1088
                                                   options:MTLResourceStorageModeShared];
        id<MTLBuffer> ss_buf  = [device newBufferWithLength:n * 32
                                                    options:MTLResourceStorageModeShared];
        id<MTLBuffer> res_buf = [device newBufferWithLength:n
                                                    options:MTLResourceStorageModeShared];
        uint32_t n_u32 = (uint32_t)n;
        id<MTLBuffer> n_buf   = [device newBufferWithBytes:&n_u32
                                                    length:sizeof(n_u32)
                                                   options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> cmd = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:pipeline];
        [enc setBuffer:sks_buf offset:0 atIndex:0];
        [enc setBuffer:cts_buf offset:0 atIndex:1];
        [enc setBuffer:ss_buf  offset:0 atIndex:2];
        [enc setBuffer:res_buf offset:0 atIndex:3];
        [enc setBuffer:n_buf   offset:0 atIndex:4];

        NSUInteger tg_max = pipeline.maxTotalThreadsPerThreadgroup;
        NSUInteger tg_w   = tg_max < 64 ? tg_max : 64;
        if (tg_w > n) tg_w = n;
        MTLSize threads_per_grid = MTLSizeMake(n, 1, 1);
        MTLSize threads_per_tg   = MTLSizeMake(tg_w, 1, 1);
        [enc dispatchThreads:threads_per_grid threadsPerThreadgroup:threads_per_tg];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        std::memcpy(shared_secrets, [ss_buf contents],  n * 32);
        std::memcpy(results,        [res_buf contents], n);
    }
    return 0;
}

extern "C" int mlkem_shake128_metal(
    const uint8_t* inputs,
    const uint32_t* input_offsets,
    const uint32_t* input_lens,
    const uint32_t* output_lens,
    size_t          n,
    uint8_t*        outputs,
    const char*     metallib_path) {
    return dispatch_shake(@"mlkem_shake128_jobs",
                          inputs, input_offsets, input_lens, output_lens,
                          n, outputs, metallib_path);
}

extern "C" int mlkem_shake256_metal(
    const uint8_t* inputs,
    const uint32_t* input_offsets,
    const uint32_t* input_lens,
    const uint32_t* output_lens,
    size_t          n,
    uint8_t*        outputs,
    const char*     metallib_path) {
    return dispatch_shake(@"mlkem_shake256_jobs",
                          inputs, input_offsets, input_lens, output_lens,
                          n, outputs, metallib_path);
}

#endif  // __APPLE__ && __OBJC__

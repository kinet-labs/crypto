// Metal-side test driver for the BLS12-381 G2 kernels.
// Loads bls_g2.metallib (built from bls_g2.metal), dispatches each kernel
// over the oracle-provided inputs, and byte-compares against blst output.
//
// Workgroup size 1x1x1 → all threads independent → fully deterministic.

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include "vectors_g2.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace
{
struct OpResult {
    std::string name;
    size_t       n_pass = 0;
    size_t       n_fail = 0;
    size_t       elem_bytes = 0;
    size_t       first_fail_idx = SIZE_MAX;
    std::vector<uint8_t> first_fail_metal;
    std::vector<uint8_t> first_fail_oracle;
};

id<MTLDevice>       g_device;
id<MTLCommandQueue> g_queue;
id<MTLLibrary>      g_lib;

void die(const std::string& msg)
{
    fprintf(stderr, "FATAL: %s\n", msg.c_str());
    std::exit(1);
}

id<MTLBuffer> make_buf(const void* data, size_t bytes)
{
    return [g_device newBufferWithBytes:data length:bytes
                                options:MTLResourceStorageModeShared];
}

id<MTLBuffer> make_out(size_t bytes)
{
    return [g_device newBufferWithLength:bytes
                                 options:MTLResourceStorageModeShared];
}

void run_binary(const char* kname, const void* a, const void* b,
                size_t a_elem, size_t b_elem,
                void* out, size_t out_elem, size_t count)
{
    NSError* err = nil;
    id<MTLFunction> fn = [g_lib newFunctionWithName:[NSString stringWithUTF8String:kname]];
    if (!fn) die(std::string("missing kernel: ") + kname);
    id<MTLComputePipelineState> pso =
        [g_device newComputePipelineStateWithFunction:fn error:&err];
    if (!pso) die(std::string("pso failed: ") + kname);

    id<MTLBuffer> bA   = make_buf(a, a_elem * count);
    id<MTLBuffer> bB   = make_buf(b, b_elem * count);
    id<MTLBuffer> bOut = make_out(out_elem * count);
    uint32_t n32 = static_cast<uint32_t>(count);
    id<MTLBuffer> bN = make_buf(&n32, sizeof(n32));

    id<MTLCommandBuffer> cb = [g_queue commandBuffer];
    id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
    [enc setComputePipelineState:pso];
    [enc setBuffer:bA   offset:0 atIndex:0];
    [enc setBuffer:bB   offset:0 atIndex:1];
    [enc setBuffer:bOut offset:0 atIndex:2];
    [enc setBuffer:bN   offset:0 atIndex:3];

    NSUInteger tg = std::min<NSUInteger>(pso.maxTotalThreadsPerThreadgroup, 32);
    [enc dispatchThreads:MTLSizeMake(count, 1, 1)
        threadsPerThreadgroup:MTLSizeMake(tg, 1, 1)];
    [enc endEncoding];
    [cb commit];
    [cb waitUntilCompleted];

    std::memcpy(out, bOut.contents, out_elem * count);
}

void run_unary(const char* kname, const void* a, size_t a_elem,
               void* out, size_t out_elem, size_t count)
{
    NSError* err = nil;
    id<MTLFunction> fn = [g_lib newFunctionWithName:[NSString stringWithUTF8String:kname]];
    if (!fn) die(std::string("missing kernel: ") + kname);
    id<MTLComputePipelineState> pso =
        [g_device newComputePipelineStateWithFunction:fn error:&err];
    if (!pso) die(std::string("pso failed: ") + kname);

    id<MTLBuffer> bA   = make_buf(a, a_elem * count);
    id<MTLBuffer> bOut = make_out(out_elem * count);
    uint32_t n32 = static_cast<uint32_t>(count);
    id<MTLBuffer> bN = make_buf(&n32, sizeof(n32));

    id<MTLCommandBuffer> cb = [g_queue commandBuffer];
    id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
    [enc setComputePipelineState:pso];
    [enc setBuffer:bA   offset:0 atIndex:0];
    [enc setBuffer:bOut offset:0 atIndex:1];
    [enc setBuffer:bN   offset:0 atIndex:2];

    NSUInteger tg = std::min<NSUInteger>(pso.maxTotalThreadsPerThreadgroup, 32);
    [enc dispatchThreads:MTLSizeMake(count, 1, 1)
        threadsPerThreadgroup:MTLSizeMake(tg, 1, 1)];
    [enc endEncoding];
    [cb commit];
    [cb waitUntilCompleted];

    std::memcpy(out, bOut.contents, out_elem * count);
}

// Scalar mult kernel takes (in, out, n, nbits)
void run_scalar_mult(const void* in_data, size_t in_elem,
                     void* out, size_t out_elem,
                     size_t count, uint32_t nbits)
{
    NSError* err = nil;
    id<MTLFunction> fn = [g_lib newFunctionWithName:@"k_p2_scalar_mult"];
    if (!fn) die("missing kernel: k_p2_scalar_mult");
    id<MTLComputePipelineState> pso =
        [g_device newComputePipelineStateWithFunction:fn error:&err];
    if (!pso) die("pso failed: k_p2_scalar_mult");

    id<MTLBuffer> bIn  = make_buf(in_data, in_elem * count);
    id<MTLBuffer> bOut = make_out(out_elem * count);
    uint32_t n32 = static_cast<uint32_t>(count);
    id<MTLBuffer> bN     = make_buf(&n32, sizeof(n32));
    id<MTLBuffer> bNbits = make_buf(&nbits, sizeof(nbits));

    id<MTLCommandBuffer> cb = [g_queue commandBuffer];
    id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
    [enc setComputePipelineState:pso];
    [enc setBuffer:bIn    offset:0 atIndex:0];
    [enc setBuffer:bOut   offset:0 atIndex:1];
    [enc setBuffer:bN     offset:0 atIndex:2];
    [enc setBuffer:bNbits offset:0 atIndex:3];

    NSUInteger tg = std::min<NSUInteger>(pso.maxTotalThreadsPerThreadgroup, 32);
    [enc dispatchThreads:MTLSizeMake(count, 1, 1)
        threadsPerThreadgroup:MTLSizeMake(tg, 1, 1)];
    [enc endEncoding];
    [cb commit];
    [cb waitUntilCompleted];

    std::memcpy(out, bOut.contents, out_elem * count);
}

OpResult compare(const char* op, size_t elem_bytes,
                 const void* metal_out, const void* oracle, size_t count)
{
    OpResult r;
    r.name = op;
    r.elem_bytes = elem_bytes;

    const uint8_t* m = static_cast<const uint8_t*>(metal_out);
    const uint8_t* o = static_cast<const uint8_t*>(oracle);
    for (size_t i = 0; i < count; i++) {
        if (std::memcmp(m + i*elem_bytes, o + i*elem_bytes, elem_bytes) == 0) {
            r.n_pass++;
        } else {
            r.n_fail++;
            if (r.first_fail_idx == SIZE_MAX) {
                r.first_fail_idx = i;
                r.first_fail_metal.assign(m + i*elem_bytes, m + (i+1)*elem_bytes);
                r.first_fail_oracle.assign(o + i*elem_bytes, o + (i+1)*elem_bytes);
            }
        }
    }
    return r;
}

void print_byte_dump(const char* label, const uint8_t* data, size_t n)
{
    printf("  %s: ", label);
    for (size_t i = 0; i < n; i++) {
        printf("%02x", data[i]);
        if ((i+1) % 32 == 0 && i+1 < n) printf("\n            ");
        else if (i+1 < n) printf(" ");
    }
    printf("\n");
}

}  // namespace

int main(int argc, char** argv)
{
    @autoreleasepool {
        g_device = MTLCreateSystemDefaultDevice();
        if (!g_device) die("no Metal device");
        g_queue = [g_device newCommandQueue];

        if (argc < 2) die("usage: bls_g2_test <metallib_path>");
        NSString* libPath = [NSString stringWithUTF8String:argv[1]];
        NSError*  err = nil;
        NSURL* url = [NSURL fileURLWithPath:libPath];
        g_lib = [g_device newLibraryWithURL:url error:&err];
        if (!g_lib) die(std::string("library load failed: ") +
                        [[err localizedDescription] UTF8String]);

        std::vector<OpResult> results;

        // --- p2_jac_add ---
        {
            std::vector<uint8_t> out(kG2N * kP2Bytes, 0);
            run_binary("k_p2_jac_add", kG2AddA, kG2AddB,
                       kP2Bytes, kP2Bytes, out.data(), kP2Bytes, kG2N);
            results.push_back(compare("p2_jac_add", kP2Bytes, out.data(),
                                       kG2AddOut, kG2N));
        }

        // --- p2_jac_dbl ---
        {
            std::vector<uint8_t> out(kG2N * kP2Bytes, 0);
            run_unary("k_p2_jac_dbl", kG2DblIn, kP2Bytes,
                      out.data(), kP2Bytes, kG2N);
            results.push_back(compare("p2_jac_dbl", kP2Bytes, out.data(),
                                       kG2DblOut, kG2N));
        }

        // --- p2_mixed_add (Jacobian + affine) ---
        {
            std::vector<uint8_t> out(kG2N * kP2Bytes, 0);
            run_binary("k_p2_mixed_add", kG2MixedA, kG2MixedB,
                       kP2Bytes, kP2AffBytes,
                       out.data(), kP2Bytes, kG2N);
            results.push_back(compare("p2_mixed_add", kP2Bytes, out.data(),
                                       kG2MixedOut, kG2N));
        }

        // --- p2_scalar_mult (output: P2Aff) ---
        {
            std::vector<uint8_t> out(kG2ScalarN * kP2AffBytes, 0);
            run_scalar_mult(kG2ScalarIn, kG2ScalarInBytes,
                            out.data(), kP2AffBytes,
                            kG2ScalarN, (uint32_t)kG2ScalarBits);
            results.push_back(compare("p2_scalar_mult", kP2AffBytes, out.data(),
                                       kG2ScalarOut, kG2ScalarN));
        }

        // --- Report ---
        size_t total_pass = 0, total_fail = 0;
        printf("=== BLS12-381 G2 vs blst (Metal kernels) ===\n");
        for (auto& r : results) {
            printf("  %-18s  pass=%3zu  fail=%3zu  (%zu B/elem)\n",
                   r.name.c_str(), r.n_pass, r.n_fail, r.elem_bytes);
            total_pass += r.n_pass;
            total_fail += r.n_fail;
            if (r.n_fail > 0 && r.first_fail_idx != SIZE_MAX) {
                printf("    first fail at vector idx=%zu:\n", r.first_fail_idx);
                print_byte_dump("metal ", r.first_fail_metal.data(),  r.elem_bytes);
                print_byte_dump("oracle", r.first_fail_oracle.data(), r.elem_bytes);
            }
        }
        printf("---------------------------------------------------\n");
        printf("  TOTAL: %zu pass, %zu fail (over %zu vectors)\n",
               total_pass, total_fail, total_pass + total_fail);

        return total_fail == 0 ? 0 : 1;
    }
}

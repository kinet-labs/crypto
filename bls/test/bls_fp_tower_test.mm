// Metal-side test for BLS12-381 Fp2/Fp6/Fp12 arithmetic.
//
// 1. Load test vectors from auto-generated vectors_fp_tower.h (oracle is blst).
// 2. For each operation: upload inputs, dispatch the matching Metal kernel,
//    download outputs, compare every byte to the blst-generated reference.
// 3. Report pass/fail per op + emit one full byte-level dump for the report.

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include "vectors_fp_tower.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace
{
struct OpResult {
    std::string name;
    size_t       n_pass;
    size_t       n_fail;
    size_t       elem_bytes;
    size_t       first_fail_idx;     // SIZE_MAX if no failure
    std::vector<uint8_t> first_fail_metal;
    std::vector<uint8_t> first_fail_oracle;
};

id<MTLCommandQueue> g_queue;
id<MTLDevice>       g_device;
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

// Run a kernel that takes (a, b, out, n) over `count` elements.
void run_binary(const char* kname, const void* a, const void* b,
                void* out, size_t elem_bytes, size_t count)
{
    NSError* err = nil;
    id<MTLFunction> fn = [g_lib newFunctionWithName:[NSString stringWithUTF8String:kname]];
    if (!fn) die(std::string("missing kernel: ") + kname);
    id<MTLComputePipelineState> pso =
        [g_device newComputePipelineStateWithFunction:fn error:&err];
    if (!pso) die(std::string("pso failed: ") + kname);

    id<MTLBuffer> bA   = make_buf(a, elem_bytes * count);
    id<MTLBuffer> bB   = make_buf(b, elem_bytes * count);
    id<MTLBuffer> bOut = make_out(elem_bytes * count);
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

    std::memcpy(out, bOut.contents, elem_bytes * count);
}

// Run a kernel that takes (a, out, n) over `count` elements.
void run_unary(const char* kname, const void* a, void* out,
               size_t elem_bytes, size_t count)
{
    NSError* err = nil;
    id<MTLFunction> fn = [g_lib newFunctionWithName:[NSString stringWithUTF8String:kname]];
    if (!fn) die(std::string("missing kernel: ") + kname);
    id<MTLComputePipelineState> pso =
        [g_device newComputePipelineStateWithFunction:fn error:&err];
    if (!pso) die(std::string("pso failed: ") + kname);

    id<MTLBuffer> bA   = make_buf(a, elem_bytes * count);
    id<MTLBuffer> bOut = make_out(elem_bytes * count);
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

    std::memcpy(out, bOut.contents, elem_bytes * count);
}

OpResult compare(const char* op, size_t elem_bytes,
                 const void* metal_out, const void* oracle, size_t count)
{
    OpResult r;
    r.name = op;
    r.elem_bytes = elem_bytes;
    r.n_pass = 0;
    r.n_fail = 0;
    r.first_fail_idx = SIZE_MAX;

    const uint8_t* m = static_cast<const uint8_t*>(metal_out);
    const uint8_t* o = static_cast<const uint8_t*>(oracle);
    for (size_t i = 0; i < count; i++) {
        if (std::memcmp(m + i*elem_bytes, o + i*elem_bytes, elem_bytes) == 0) {
            r.n_pass++;
        } else {
            r.n_fail++;
            if (r.first_fail_idx == SIZE_MAX) {
                r.first_fail_idx = i;
                r.first_fail_metal.assign(m + i*elem_bytes,
                                          m + (i+1)*elem_bytes);
                r.first_fail_oracle.assign(o + i*elem_bytes,
                                           o + (i+1)*elem_bytes);
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

        // Load metallib path from CLI.
        if (argc < 2) die("usage: bls_fp_tower_test <metallib_path>");
        NSString* libPath = [NSString stringWithUTF8String:argv[1]];
        NSError* err = nil;
        NSURL* url = [NSURL fileURLWithPath:libPath];
        g_lib = [g_device newLibraryWithURL:url error:&err];
        if (!g_lib) die(std::string("library load failed: ") +
                        [[err localizedDescription] UTF8String]);

        std::vector<OpResult> results;
        std::vector<uint8_t> buf;

        // ---------- Fp inversion diagnostic ----------
        buf.assign(kNVectors * kFp2Bytes, 0);
        run_unary("k_fp_inv_diag", kFpInvIn_bytes, buf.data(),
                  kFp2Bytes, kNVectors);
        results.push_back(compare("fp_inv (diag)", kFp2Bytes, buf.data(),
                                  kFpInvOut_bytes, kNVectors));

        // ---------- Fp2 ----------
        buf.assign(kNVectors * kFp2Bytes, 0);
        run_binary("k_fp2_add", kFp2A_bytes, kFp2B_bytes, buf.data(),
                   kFp2Bytes, kNVectors);
        results.push_back(compare("fp2_add", kFp2Bytes, buf.data(),
                                  kFp2Add_bytes, kNVectors));

        run_binary("k_fp2_sub", kFp2A_bytes, kFp2B_bytes, buf.data(),
                   kFp2Bytes, kNVectors);
        results.push_back(compare("fp2_sub", kFp2Bytes, buf.data(),
                                  kFp2Sub_bytes, kNVectors));

        run_binary("k_fp2_mul", kFp2A_bytes, kFp2B_bytes, buf.data(),
                   kFp2Bytes, kNVectors);
        results.push_back(compare("fp2_mul", kFp2Bytes, buf.data(),
                                  kFp2Mul_bytes, kNVectors));

        run_unary("k_fp2_sqr", kFp2A_bytes, buf.data(),
                  kFp2Bytes, kNVectors);
        results.push_back(compare("fp2_sqr", kFp2Bytes, buf.data(),
                                  kFp2Sqr_bytes, kNVectors));

        run_unary("k_fp2_inv", kFp2A_bytes, buf.data(),
                  kFp2Bytes, kNVectors);
        results.push_back(compare("fp2_inv", kFp2Bytes, buf.data(),
                                  kFp2Inv_bytes, kNVectors));

        run_unary("k_fp2_conj", kFp2A_bytes, buf.data(),
                  kFp2Bytes, kNVectors);
        results.push_back(compare("fp2_conj", kFp2Bytes, buf.data(),
                                  kFp2Conj_bytes, kNVectors));

        // ---------- Fp6 ----------
        buf.assign(kNVectors * kFp6Bytes, 0);
        run_binary("k_fp6_add", kFp6A_bytes, kFp6B_bytes, buf.data(),
                   kFp6Bytes, kNVectors);
        results.push_back(compare("fp6_add", kFp6Bytes, buf.data(),
                                  kFp6Add_bytes, kNVectors));

        run_binary("k_fp6_sub", kFp6A_bytes, kFp6B_bytes, buf.data(),
                   kFp6Bytes, kNVectors);
        results.push_back(compare("fp6_sub", kFp6Bytes, buf.data(),
                                  kFp6Sub_bytes, kNVectors));

        run_binary("k_fp6_mul", kFp6A_bytes, kFp6B_bytes, buf.data(),
                   kFp6Bytes, kNVectors);
        results.push_back(compare("fp6_mul", kFp6Bytes, buf.data(),
                                  kFp6Mul_bytes, kNVectors));

        run_unary("k_fp6_sqr", kFp6A_bytes, buf.data(),
                  kFp6Bytes, kNVectors);
        results.push_back(compare("fp6_sqr", kFp6Bytes, buf.data(),
                                  kFp6Sqr_bytes, kNVectors));

        run_unary("k_fp6_inv", kFp6A_bytes, buf.data(),
                  kFp6Bytes, kNVectors);
        results.push_back(compare("fp6_inv", kFp6Bytes, buf.data(),
                                  kFp6Inv_bytes, kNVectors));

        // ---------- Fp12 ----------
        buf.assign(kNVectors * kFp12Bytes, 0);
        run_binary("k_fp12_add", kFp12A_bytes, kFp12B_bytes, buf.data(),
                   kFp12Bytes, kNVectors);
        results.push_back(compare("fp12_add", kFp12Bytes, buf.data(),
                                  kFp12Add_bytes, kNVectors));

        run_binary("k_fp12_sub", kFp12A_bytes, kFp12B_bytes, buf.data(),
                   kFp12Bytes, kNVectors);
        results.push_back(compare("fp12_sub", kFp12Bytes, buf.data(),
                                  kFp12Sub_bytes, kNVectors));

        run_binary("k_fp12_mul", kFp12A_bytes, kFp12B_bytes, buf.data(),
                   kFp12Bytes, kNVectors);
        results.push_back(compare("fp12_mul", kFp12Bytes, buf.data(),
                                  kFp12Mul_bytes, kNVectors));

        run_unary("k_fp12_sqr", kFp12A_bytes, buf.data(),
                  kFp12Bytes, kNVectors);
        results.push_back(compare("fp12_sqr", kFp12Bytes, buf.data(),
                                  kFp12Sqr_bytes, kNVectors));

        run_unary("k_fp12_inv", kFp12A_bytes, buf.data(),
                  kFp12Bytes, kNVectors);
        results.push_back(compare("fp12_inv", kFp12Bytes, buf.data(),
                                  kFp12Inv_bytes, kNVectors));

        run_unary("k_fp12_conj", kFp12A_bytes, buf.data(),
                  kFp12Bytes, kNVectors);
        results.push_back(compare("fp12_conj", kFp12Bytes, buf.data(),
                                  kFp12Conj_bytes, kNVectors));

        run_unary("k_fp12_cyclo_sqr", kFp12CycloIn_bytes, buf.data(),
                  kFp12Bytes, kNVectors);
        results.push_back(compare("fp12_cyclotomic_sqr", kFp12Bytes, buf.data(),
                                  kFp12CycloOut_bytes, kNVectors));

        // -------- Report --------
        size_t total_pass = 0, total_fail = 0;
        printf("=== BLS12-381 Fp tower vs blst (Metal kernels) ===\n");
        for (auto& r : results) {
            printf("  %-22s  pass=%3zu  fail=%3zu  (%zu B/elem)\n",
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

        // Always emit one full equality dump from fp12_mul for the public report.
        if (total_pass > 0) {
            // Re-run fp12_mul to get a fresh metal output buffer for vector 42.
            std::vector<uint8_t> mbuf(kNVectors * kFp12Bytes);
            run_binary("k_fp12_mul", kFp12A_bytes, kFp12B_bytes, mbuf.data(),
                       kFp12Bytes, kNVectors);
            const size_t IDX = 42;
            const uint8_t* mptr = mbuf.data() + IDX * kFp12Bytes;
            const uint8_t* optr = kFp12Mul_bytes + IDX * kFp12Bytes;
            const bool eq = std::memcmp(mptr, optr, kFp12Bytes) == 0;
            printf("\nVector fp12_mul[%zu]:  %s\n",
                   IDX, eq ? "EQUAL" : "DIFFER");
            print_byte_dump("blst  ", optr, kFp12Bytes);
            print_byte_dump("metal ", mptr, kFp12Bytes);
        }

        return total_fail == 0 ? 0 : 1;
    }
}

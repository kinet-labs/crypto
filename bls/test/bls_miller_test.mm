// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Metal-side test driver for the BLS12-381 optimal-ate Miller loop.
//
// The loop is split across four bounded kernels (init, step_add, step_dbl,
// finalize) and orchestrated from the host. Every arithmetic op runs on
// Metal — the host only sequences kernel dispatches. This split is required
// because a single monolithic Miller-loop kernel exceeds the
// MetalCompilerService XPC compile budget on this machine class.
//
// Workgroup size 1×1×1 → byte-deterministic per-thread output.
// 100 (P, Q) vectors compared byte-for-byte against blst_miller_loop.

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include "vectors_miller.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace
{
constexpr size_t kP2Bytes  = 288;     // sizeof(blst_p2)
constexpr size_t kFp2Bytes = 96;      // sizeof(blst_fp2)

// blst_t::miller_loop loop sequence (pairing.c:166-175):
//   first dbl is fused into init
//   then phases of "1 add + n dbls" with n = {2, 3, 9, 32, 16}
const uint32_t kPhases[5] = { 2u, 3u, 9u, 32u, 16u };

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

id<MTLBuffer> make_zero(size_t bytes)
{
    return [g_device newBufferWithLength:bytes
                                 options:MTLResourceStorageModeShared];
}

id<MTLComputePipelineState> make_pso(const char* name)
{
    NSError* err = nil;
    id<MTLFunction> fn =
        [g_lib newFunctionWithName:[NSString stringWithUTF8String:name]];
    if (!fn) die(std::string("missing kernel: ") + name);
    id<MTLComputePipelineState> pso =
        [g_device newComputePipelineStateWithFunction:fn error:&err];
    if (!pso) {
        std::string msg = "pso failed: ";
        msg += name;
        msg += ": ";
        if (err) msg += [[err localizedDescription] UTF8String];
        die(msg);
    }
    return pso;
}

void dispatch_pso(id<MTLComputePipelineState> pso,
                  std::vector<id<MTLBuffer>> bufs,
                  size_t count)
{
    id<MTLCommandBuffer> cb = [g_queue commandBuffer];
    id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
    [enc setComputePipelineState:pso];
    for (NSUInteger i = 0; i < bufs.size(); i++) {
        [enc setBuffer:bufs[i] offset:0 atIndex:i];
    }
    NSUInteger tg = std::min<NSUInteger>(pso.maxTotalThreadsPerThreadgroup, 16);
    [enc dispatchThreads:MTLSizeMake(count, 1, 1)
        threadsPerThreadgroup:MTLSizeMake(tg, 1, 1)];
    [enc endEncoding];
    [cb commit];
    [cb waitUntilCompleted];
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

        if (argc < 2) die("usage: bls_miller_test <metallib_path>");
        NSString* libPath = [NSString stringWithUTF8String:argv[1]];
        NSError*  err = nil;
        NSURL* url = [NSURL fileURLWithPath:libPath];
        g_lib = [g_device newLibraryWithURL:url error:&err];
        if (!g_lib) die(std::string("library load failed: ") +
                        [[err localizedDescription] UTF8String]);

        // ---- Compile each kernel once. ----
        // Six kernels split the work so each one's PSO compile fits within
        // the MetalCompilerService XPC budget. Per blst pairing.c:
        //   init          : T = Q, ret = unpack(line_dbl)        — once
        //   add_T_and_line: T = T + Q, write line                — phase entry
        //   fold_line     : ret *= line                          — sparse mul
        //   sqr_ret       : ret = ret^2                          — squaring
        //   dbl_T_and_line: T = 2*T, write line                  — doubling
        //   finalize      : out = conj(ret)                      — once
        id<MTLComputePipelineState> pso_init     = make_pso("k_miller_init");
        id<MTLComputePipelineState> pso_add_T    = make_pso("k_miller_add_T_and_line");
        id<MTLComputePipelineState> pso_dbl_T    = make_pso("k_miller_dbl_T_and_line");
        id<MTLComputePipelineState> pso_sqr_ret  = make_pso("k_miller_sqr_ret");
        id<MTLComputePipelineState> pso_fold     = make_pso("k_miller_fold_line");
        id<MTLComputePipelineState> pso_final    = make_pso("k_miller_finalize");

        // ---- State buffers shared across dispatches. ----
        size_t N = kMillerN;
        constexpr size_t kLineBufBytes = 3 * kFp2Bytes;  // sizeof(LineBuf)
        id<MTLBuffer> bIn   = make_buf(kMillerIn, kMillerInBytes  * N);
        id<MTLBuffer> bT    = make_zero(kP2Bytes        * N);
        id<MTLBuffer> bRet  = make_zero(kMillerOutBytes * N);
        id<MTLBuffer> bPx2  = make_zero(kFp2Bytes       * N);
        id<MTLBuffer> bLine = make_zero(kLineBufBytes   * N);
        id<MTLBuffer> bOut  = make_zero(kMillerOutBytes * N);
        uint32_t n32 = static_cast<uint32_t>(N);
        id<MTLBuffer> bN    = make_buf(&n32, sizeof(n32));

        // ---- Init: T = Q (Z=1), Px2, ret = unpack(line_dbl(T,T)). ----
        dispatch_pso(pso_init, { bIn, bT, bRet, bPx2, bN }, N);

        // ---- 5 phases: { add+fold ; (dbl+sqr+fold) × n_phase }. ----
        for (int phase = 0; phase < 5; phase++) {
            // add: T = T + Q ; line = line_add(...)
            dispatch_pso(pso_add_T, { bIn, bT, bLine, bPx2, bN }, N);
            // fold: ret *= line
            dispatch_pso(pso_fold, { bRet, bLine, bN }, N);

            for (uint32_t k = 0; k < kPhases[phase]; k++) {
                // sqr: ret = ret^2
                dispatch_pso(pso_sqr_ret, { bRet, bN }, N);
                // dbl: T = 2*T ; line = line_dbl(...)
                dispatch_pso(pso_dbl_T, { bT, bLine, bPx2, bN }, N);
                // fold: ret *= line
                dispatch_pso(pso_fold, { bRet, bLine, bN }, N);
            }
        }

        // ---- Finalize: out = conj(ret). ----
        dispatch_pso(pso_final, { bRet, bOut, bN }, N);

        // ---- Compare ----
        const uint8_t* metal_out = static_cast<const uint8_t*>(bOut.contents);
        size_t pass = 0, fail = 0, first_fail = SIZE_MAX;
        for (size_t i = 0; i < N; i++) {
            const uint8_t* m = metal_out  + i * kMillerOutBytes;
            const uint8_t* o = kMillerOut + i * kMillerOutBytes;
            if (std::memcmp(m, o, kMillerOutBytes) == 0) pass++;
            else { fail++; if (first_fail == SIZE_MAX) first_fail = i; }
        }

        printf("=== BLS12-381 Miller loop vs blst (Metal kernels) ===\n");
        printf("  miller_loop  pass=%3zu  fail=%3zu  (%zu B/elem)\n",
               pass, fail, kMillerOutBytes);
        if (fail > 0 && first_fail != SIZE_MAX) {
            printf("  first fail at vector idx=%zu:\n", first_fail);
            print_byte_dump("metal ",
                metal_out  + first_fail * kMillerOutBytes, kMillerOutBytes);
            print_byte_dump("oracle",
                kMillerOut + first_fail * kMillerOutBytes, kMillerOutBytes);
        }
        printf("---------------------------------------------------\n");
        printf("  TOTAL: %zu pass, %zu fail\n", pass, fail);

        // Always emit one full equality dump (vector idx 7) for the report.
        if (pass > 0) {
            const size_t IDX = 7;
            const uint8_t* mptr = metal_out  + IDX * kMillerOutBytes;
            const uint8_t* optr = kMillerOut + IDX * kMillerOutBytes;
            const bool eq = std::memcmp(mptr, optr, kMillerOutBytes) == 0;
            printf("\nVector miller_loop[%zu]:  %s\n",
                   IDX, eq ? "EQUAL" : "DIFFER");
            print_byte_dump("blst  ", optr, kMillerOutBytes);
            print_byte_dump("metal ", mptr, kMillerOutBytes);
        }

        return fail == 0 ? 0 : 1;
    }
}

// Metal-side test driver for the BLS12-381 final exponentiation.
//
// Mirrors blst src/pairing.c::final_exp() byte-for-byte. Six bounded kernels
// (easy, cyclo_sqr, mul, conj, frobenius, copy) compose the addchain via
// host-orchestrated dispatches. Workgroup 1×1×1 keeps byte-determinism.
//
// 100 random Fp12 inputs (each generated as blst_miller_loop output of a
// random (P, Q) pair, so they are valid cyclotomic-form pre-final-exp values)
// are compared byte-for-byte against blst_final_exp.

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include "vectors_final_exp.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace
{
constexpr size_t kFp12Bytes = 576;

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

// =============================================================================
// Host-side orchestration helpers — mirror blst pairing.c step-by-step.
// =============================================================================

struct FE {
    id<MTLComputePipelineState> inv;
    id<MTLComputePipelineState> cyclo_sqr;
    id<MTLComputePipelineState> mul;
    id<MTLComputePipelineState> conj;
    id<MTLComputePipelineState> frob;
    id<MTLComputePipelineState> copy;
    id<MTLBuffer>               nbuf;
    size_t                      n;
};

void fe_inv(FE& fe, id<MTLBuffer> in_buf, id<MTLBuffer> out_buf)
{
    dispatch_pso(fe.inv, { in_buf, out_buf, fe.nbuf }, fe.n);
}

void fe_cyclo_sqr(FE& fe, id<MTLBuffer> buf)
{
    dispatch_pso(fe.cyclo_sqr, { buf, fe.nbuf }, fe.n);
}

void fe_mul(FE& fe, id<MTLBuffer> a, id<MTLBuffer> b, id<MTLBuffer> out)
{
    dispatch_pso(fe.mul, { a, b, out, fe.nbuf }, fe.n);
}

void fe_conj(FE& fe, id<MTLBuffer> buf)
{
    dispatch_pso(fe.conj, { buf, fe.nbuf }, fe.n);
}

void fe_frobenius(FE& fe, id<MTLBuffer> buf, uint32_t n_pow)
{
    id<MTLBuffer> bp = make_buf(&n_pow, sizeof(n_pow));
    dispatch_pso(fe.frob, { buf, fe.nbuf, bp }, fe.n);
}

void fe_copy(FE& fe, id<MTLBuffer> src, id<MTLBuffer> dst)
{
    dispatch_pso(fe.copy, { src, dst, fe.nbuf }, fe.n);
}

// raise_to_z_div_by_2(out, a):
//   out = a^(z/2)  via the addchain  z = 0xd201000000010000  with a final conj.
// Sequence mirrors blst pairing.c::raise_to_z_div_by_2 exactly:
//   out = cyclo_sqr(a)
//   mul_n_sqr(out, a, 2)
//   mul_n_sqr(out, a, 3)
//   mul_n_sqr(out, a, 9)
//   mul_n_sqr(out, a, 32)
//   mul_n_sqr(out, a, 15)        // 16-1
//   out = conj(out)
// Where mul_n_sqr(out, a, n) = (out *= a; out = cyclo_sqr^n(out)).
void fe_raise_to_z_div_by_2(FE& fe,
                            id<MTLBuffer> out,
                            id<MTLBuffer> a,
                            id<MTLBuffer> tmp)
{
    // out = cyclo_sqr(a)
    fe_copy(fe, a, out);
    fe_cyclo_sqr(fe, out);

    auto mul_n_sqr = [&](size_t n) {
        // out *= a
        fe_mul(fe, out, a, tmp);
        fe_copy(fe, tmp, out);
        // out = cyclo_sqr^n(out)
        for (size_t i = 0; i < n; i++) fe_cyclo_sqr(fe, out);
    };

    mul_n_sqr(2);
    mul_n_sqr(3);
    mul_n_sqr(9);
    mul_n_sqr(32);
    mul_n_sqr(15);   // 16-1

    fe_conj(fe, out);
}

// raise_to_z(out, a) = raise_to_z_div_by_2(out, a); out = cyclo_sqr(out);
void fe_raise_to_z(FE& fe, id<MTLBuffer> out, id<MTLBuffer> a, id<MTLBuffer> tmp)
{
    fe_raise_to_z_div_by_2(fe, out, a, tmp);
    fe_cyclo_sqr(fe, out);
}

// final_exp(ret_out, f) — runs the blst chain on Metal.
// ret_out, f are device buffers of (N * Fp12) bytes.  The remaining buffers
// (y0, y1, y2, y3, tmp) are scratch slabs of the same size.
void fe_final_exp(FE& fe,
                  id<MTLBuffer> in_f,
                  id<MTLBuffer> ret,
                  id<MTLBuffer> y0,
                  id<MTLBuffer> y1,
                  id<MTLBuffer> y2,
                  id<MTLBuffer> y3,
                  id<MTLBuffer> tmp)
{
    // ---- easy part ----
    //   y1 = conj(f);  y2 = inv(f);  t = y1*y2;  ret = t * frob(t, 2)
    // Decomposed across small kernels — fp12_inv alone is the fattest single
    // op so it is its own kernel; everything else uses copy/conj/frob/mul.
    fe_copy(fe, in_f, y1);
    fe_conj(fe, y1);                           // y1 = conj(f)
    fe_inv(fe, in_f, y2);                      // y2 = inv(f)
    fe_mul(fe, y1, y2, ret);                   // ret = y1 * y2 = f^(p^6-1)
    fe_copy(fe, ret, y2);
    fe_frobenius(fe, y2, 2u);                  // y2 = frob(ret, 2)
    fe_mul(fe, ret, y2, tmp);
    fe_copy(fe, tmp, ret);                     // ret = ret * y2 = ^(p^2+1)

    // ---- hard part (zkcrypto chain) ----
    // y0 = cyclo_sqr(ret)
    fe_copy(fe, ret, y0);
    fe_cyclo_sqr(fe, y0);

    // y1 = raise_to_z(y0)
    fe_raise_to_z(fe, y1, y0, tmp);

    // y2 = raise_to_z_div_by_2(y1)
    fe_raise_to_z_div_by_2(fe, y2, y1, tmp);

    // y3 = ret;  y3 = conj(y3)
    fe_copy(fe, ret, y3);
    fe_conj(fe, y3);

    // y1 = y1 * y3
    fe_mul(fe, y1, y3, tmp); fe_copy(fe, tmp, y1);

    // y1 = conj(y1)
    fe_conj(fe, y1);

    // y1 = y1 * y2
    fe_mul(fe, y1, y2, tmp); fe_copy(fe, tmp, y1);

    // y2 = raise_to_z(y1)
    fe_raise_to_z(fe, y2, y1, tmp);

    // y3 = raise_to_z(y2)
    fe_raise_to_z(fe, y3, y2, tmp);

    // y1 = conj(y1)
    fe_conj(fe, y1);

    // y3 = y3 * y1
    fe_mul(fe, y3, y1, tmp); fe_copy(fe, tmp, y3);

    // y1 = conj(y1)
    fe_conj(fe, y1);

    // y1 = frob(y1, 3)
    fe_frobenius(fe, y1, 3u);

    // y2 = frob(y2, 2)
    fe_frobenius(fe, y2, 2u);

    // y1 = y1 * y2
    fe_mul(fe, y1, y2, tmp); fe_copy(fe, tmp, y1);

    // y2 = raise_to_z(y3)
    fe_raise_to_z(fe, y2, y3, tmp);

    // y2 = y2 * y0
    fe_mul(fe, y2, y0, tmp); fe_copy(fe, tmp, y2);

    // y2 = y2 * ret
    fe_mul(fe, y2, ret, tmp); fe_copy(fe, tmp, y2);

    // y1 = y1 * y2
    fe_mul(fe, y1, y2, tmp); fe_copy(fe, tmp, y1);

    // y2 = frob(y3, 1) — done out-of-place by copy + frob
    fe_copy(fe, y3, y2);
    fe_frobenius(fe, y2, 1u);

    // ret = y1 * y2
    fe_mul(fe, y1, y2, tmp); fe_copy(fe, tmp, ret);
}

}  // namespace

int main(int argc, char** argv)
{
    @autoreleasepool {
        g_device = MTLCreateSystemDefaultDevice();
        if (!g_device) die("no Metal device");
        g_queue = [g_device newCommandQueue];

        if (argc < 2) die("usage: bls_final_exp_test <metallib_path>");
        NSString* libPath = [NSString stringWithUTF8String:argv[1]];
        NSError*  err = nil;
        NSURL* url = [NSURL fileURLWithPath:libPath];
        g_lib = [g_device newLibraryWithURL:url error:&err];
        if (!g_lib) die(std::string("library load failed: ") +
                        [[err localizedDescription] UTF8String]);

        FE fe;
        fe.inv       = make_pso("k_fe_inv");
        fe.cyclo_sqr = make_pso("k_fe_cyclo_sqr");
        fe.mul       = make_pso("k_fe_mul");
        fe.conj      = make_pso("k_fe_conj");
        fe.frob      = make_pso("k_fe_frobenius");
        fe.copy      = make_pso("k_fe_copy");
        fe.n         = kFEN;
        uint32_t n32 = static_cast<uint32_t>(fe.n);
        fe.nbuf      = make_buf(&n32, sizeof(n32));

        size_t slab = kFp12Bytes * fe.n;
        id<MTLBuffer> bIn  = make_buf(kFEIn, slab);
        id<MTLBuffer> bRet = make_zero(slab);
        id<MTLBuffer> bY0  = make_zero(slab);
        id<MTLBuffer> bY1  = make_zero(slab);
        id<MTLBuffer> bY2  = make_zero(slab);
        id<MTLBuffer> bY3  = make_zero(slab);
        id<MTLBuffer> bTmp = make_zero(slab);

        fe_final_exp(fe, bIn, bRet, bY0, bY1, bY2, bY3, bTmp);

        // ---- Compare ----
        const uint8_t* metal_out = static_cast<const uint8_t*>(bRet.contents);
        size_t pass = 0, fail = 0, first_fail = SIZE_MAX;
        for (size_t i = 0; i < fe.n; i++) {
            const uint8_t* m = metal_out + i * kFp12Bytes;
            const uint8_t* o = kFEOut    + i * kFp12Bytes;
            if (std::memcmp(m, o, kFp12Bytes) == 0) pass++;
            else { fail++; if (first_fail == SIZE_MAX) first_fail = i; }
        }

        printf("=== BLS12-381 final_exp vs blst (Metal kernels) ===\n");
        printf("  final_exp  pass=%3zu  fail=%3zu  (%zu B/elem)\n",
               pass, fail, kFp12Bytes);
        if (fail > 0 && first_fail != SIZE_MAX) {
            printf("  first fail at vector idx=%zu:\n", first_fail);
            print_byte_dump("metal ",
                metal_out + first_fail * kFp12Bytes, kFp12Bytes);
            print_byte_dump("oracle",
                kFEOut    + first_fail * kFp12Bytes, kFp12Bytes);
        }
        printf("---------------------------------------------------\n");
        printf("  TOTAL: %zu pass, %zu fail\n", pass, fail);

        if (pass > 0) {
            const size_t IDX = 11;
            const uint8_t* mptr = metal_out + IDX * kFp12Bytes;
            const uint8_t* optr = kFEOut    + IDX * kFp12Bytes;
            const bool eq = std::memcmp(mptr, optr, kFp12Bytes) == 0;
            printf("\nVector final_exp[%zu]:  %s\n",
                   IDX, eq ? "EQUAL" : "DIFFER");
            print_byte_dump("blst  ", optr, kFp12Bytes);
            print_byte_dump("metal ", mptr, kFp12Bytes);
        }

        return fail == 0 ? 0 : 1;
    }
}

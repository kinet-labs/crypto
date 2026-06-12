// Host dispatcher for the combined-pair Miller-loop pipeline on Metal.
//
// One driver call runs the full Miller loop (init / add_T / dbl_T /
// sqr_ret / fold_line / finalize, sequenced per the BLS12-381 ate
// scalar |x|) over k pairs as N=k workitems, then collapses the k
// Fp12 outputs to a single product via canonical pairwise tree
// reduction.  The output is the pre-final-exponentiation Fp12 product
//
//     prod_i miller_loop(Q_i, P_i)
//
// byte-equal the CPU path
//
//     std::vector<blst_fp12> ml(k);
//     for i: blst_miller_loop(&ml[i], &Q_i, &P_i);
//     tree_reduce_fp12(ml);   // round-by-round pairwise
//     out = ml[0];            // 576-byte Fp12, NO final_exp.
//
// Caller is expected to apply final_exp() once after this routine
// (matches the multi_pair semantics used by tests).

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include "bls_combined_miller_driver.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

namespace {

// Layout constants — must match bls_miller.metal struct sizes.
constexpr size_t kP1AffBytes  = 96;     // sizeof(P1Aff) — uint384 X, Y
constexpr size_t kP2AffBytes  = 192;    // sizeof(P2Aff) — Fp2 X, Y
constexpr size_t kMillerInBytes = kP2AffBytes + kP1AffBytes;  // Q || P
constexpr size_t kP2Bytes     = 288;    // sizeof(P2) Jacobian
constexpr size_t kFp2Bytes    = 96;
constexpr size_t kFp12Bytes   = 576;
constexpr size_t kLineBytes   = 3 * kFp2Bytes;

// Miller-loop phase doubling counts (BLS12-381 ate scalar |x| bit pattern).
// Same as bls_miller_test.mm and bls_pairing_test.mm.
constexpr uint32_t kPhases[5] = { 2u, 3u, 9u, 32u, 16u };

struct Ctx {
    id<MTLDevice>       device;
    id<MTLCommandQueue> queue;
    id<MTLLibrary>      library;
    // Miller PSOs.
    id<MTLComputePipelineState> mil_init;
    id<MTLComputePipelineState> mil_add_T;
    id<MTLComputePipelineState> mil_dbl_T;
    id<MTLComputePipelineState> mil_sqr_ret;
    id<MTLComputePipelineState> mil_fold;
    id<MTLComputePipelineState> mil_finalize;
    // Tree-reduce PSO.
    id<MTLComputePipelineState> reduce;
    // Status of last load.
    int last_status;
};

std::mutex g_ctx_mu;
Ctx* g_ctx = nullptr;

const char* env_metallib_path()
{
    if (const char* p = std::getenv("BLS_COMBINED_MILLER_METALLIB")) {
        if (p[0] != '\0') return p;
    }
    return nullptr;
}

id<MTLLibrary> load_library(id<MTLDevice> dev, NSError** err_out)
{
    // Try caller-supplied env path first (CI/tests), then standard install
    // locations, then fall back to nil.
    NSMutableArray<NSString*>* paths = [NSMutableArray array];
    if (const char* envp = env_metallib_path()) {
        [paths addObject:[NSString stringWithUTF8String:envp]];
    }
    [paths addObject:@"/usr/local/share/kinet/crypto/bls_combined_miller.metallib"];
    [paths addObject:@"/usr/local/share/kinet/crypto/bls_pairing.metallib"];

    NSFileManager* fm = [NSFileManager defaultManager];
    for (NSString* p in paths) {
        if (p.length == 0) continue;
        if (![fm fileExistsAtPath:p]) continue;
        NSError* e = nil;
        id<MTLLibrary> lib = [dev newLibraryWithURL:[NSURL fileURLWithPath:p]
                                              error:&e];
        if (lib) return lib;
        if (err_out && *err_out == nil) *err_out = e;
    }
    return nil;
}

id<MTLComputePipelineState> make_pso(id<MTLLibrary> lib,
                                     id<MTLDevice>  dev,
                                     const char*    name,
                                     int*           status)
{
    NSError* e = nil;
    id<MTLFunction> f = [lib newFunctionWithName:[NSString stringWithUTF8String:name]];
    if (!f) {
        if (status) *status = -2;
        return nil;
    }
    id<MTLComputePipelineState> pso =
        [dev newComputePipelineStateWithFunction:f error:&e];
    if (!pso && status) *status = -3;
    return pso;
}

// Initialise (or reuse) the global context.  Returns nullptr on failure;
// in that case the caller should fall back to the CPU multi_pair path.
Ctx* init_or_get_ctx()
{
    std::lock_guard<std::mutex> g(g_ctx_mu);
    if (g_ctx != nullptr) return g_ctx;

    Ctx* c = new Ctx{};
    c->device = MTLCreateSystemDefaultDevice();
    if (!c->device) { c->last_status = -1; g_ctx = c; return c; }
    c->queue = [c->device newCommandQueue];

    NSError* err = nil;
    c->library = load_library(c->device, &err);
    if (!c->library) { c->last_status = -2; g_ctx = c; return c; }

    int s = 0;
    c->mil_init     = make_pso(c->library, c->device, "k_miller_init",          &s);
    c->mil_add_T    = make_pso(c->library, c->device, "k_miller_add_T_and_line", &s);
    c->mil_dbl_T    = make_pso(c->library, c->device, "k_miller_dbl_T_and_line", &s);
    c->mil_sqr_ret  = make_pso(c->library, c->device, "k_miller_sqr_ret",        &s);
    c->mil_fold     = make_pso(c->library, c->device, "k_miller_fold_line",      &s);
    c->mil_finalize = make_pso(c->library, c->device, "k_miller_finalize",       &s);
    c->reduce       = make_pso(c->library, c->device, "k_combined_miller_reduce", &s);
    if (s != 0 ||
        !c->mil_init || !c->mil_add_T || !c->mil_dbl_T ||
        !c->mil_sqr_ret || !c->mil_fold || !c->mil_finalize ||
        !c->reduce) {
        c->last_status = -3;
        g_ctx = c;
        return c;
    }
    c->last_status = 0;
    g_ctx = c;
    return c;
}

void encode_dispatch(id<MTLComputeCommandEncoder> enc,
                     id<MTLComputePipelineState> pso,
                     std::initializer_list<id<MTLBuffer>> bufs,
                     size_t threads)
{
    [enc setComputePipelineState:pso];
    NSUInteger i = 0;
    for (id<MTLBuffer> b : bufs) {
        [enc setBuffer:b offset:0 atIndex:i];
        ++i;
    }
    NSUInteger tg = MIN((NSUInteger)16, pso.maxTotalThreadsPerThreadgroup);
    [enc dispatchThreads:MTLSizeMake(threads, 1, 1)
        threadsPerThreadgroup:MTLSizeMake(tg, 1, 1)];
}

}  // namespace

extern "C" int bls_combined_miller_metal(const uint8_t* g1s,
                                         const uint8_t* g2s,
                                         size_t         k,
                                         uint8_t        fp12_out[576])
{
    if (fp12_out == nullptr) return -1;
    if (k == 0) return -1;
    if (g1s == nullptr || g2s == nullptr) return -1;

    Ctx* ctx = init_or_get_ctx();
    if (!ctx || ctx->last_status != 0) return -2;

    @autoreleasepool {
        // ---- Pack inputs in MillerIn layout: Q || P per workitem. ----
        std::vector<uint8_t> in_packed(k * kMillerInBytes);
        for (size_t i = 0; i < k; ++i) {
            std::memcpy(in_packed.data() + i * kMillerInBytes,
                        g2s + i * kP2AffBytes, kP2AffBytes);
            std::memcpy(in_packed.data() + i * kMillerInBytes + kP2AffBytes,
                        g1s + i * kP1AffBytes, kP1AffBytes);
        }

        id<MTLDevice> dev = ctx->device;
        auto buf = [&](size_t bytes) -> id<MTLBuffer> {
            return [dev newBufferWithLength:bytes
                                    options:MTLResourceStorageModeShared];
        };
        auto buf_data = [&](const void* data, size_t bytes) -> id<MTLBuffer> {
            return [dev newBufferWithBytes:data
                                    length:bytes
                                   options:MTLResourceStorageModeShared];
        };

        id<MTLBuffer> bIn   = buf_data(in_packed.data(), in_packed.size());
        id<MTLBuffer> bT    = buf(kP2Bytes    * k);
        id<MTLBuffer> bRet  = buf(kFp12Bytes  * k);
        id<MTLBuffer> bPx2  = buf(kFp2Bytes   * k);
        id<MTLBuffer> bLine = buf(kLineBytes  * k);
        id<MTLBuffer> bMOut = buf(kFp12Bytes  * k);

        // Two ping-pong Fp12 buffers for the tree reduction.  bMOut holds
        // the conjugated Miller outputs first, then alternates with bRed.
        id<MTLBuffer> bRed  = buf(kFp12Bytes  * k);

        uint32_t k32 = static_cast<uint32_t>(k);
        id<MTLBuffer> bN = buf_data(&k32, sizeof(k32));

        id<MTLCommandBuffer> cb = [ctx->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];

        // ---- Miller loop on N=k workitems. ----
        encode_dispatch(enc, ctx->mil_init, { bIn, bT, bRet, bPx2, bN }, k);
        for (int phase = 0; phase < 5; ++phase) {
            encode_dispatch(enc, ctx->mil_add_T, { bIn, bT, bLine, bPx2, bN }, k);
            encode_dispatch(enc, ctx->mil_fold,  { bRet, bLine, bN }, k);
            for (uint32_t r = 0; r < kPhases[phase]; ++r) {
                encode_dispatch(enc, ctx->mil_sqr_ret, { bRet, bN }, k);
                encode_dispatch(enc, ctx->mil_dbl_T,   { bT, bLine, bPx2, bN }, k);
                encode_dispatch(enc, ctx->mil_fold,    { bRet, bLine, bN }, k);
            }
        }
        encode_dispatch(enc, ctx->mil_finalize, { bRet, bMOut, bN }, k);

        // ---- Canonical Fp12 tree reduction over the k outputs. ----
        // round_in == bMOut, round_out == bRed; swap each round.
        id<MTLBuffer> round_in  = bMOut;
        id<MTLBuffer> round_out = bRed;
        size_t n = k;

        // For k == 1: no reduction rounds; round_in already holds the answer.
        // We hold one in-flight constant buffer per round so each kernel
        // dispatch sees the (pairs, carry) for its specific round.
        std::vector<id<MTLBuffer>> round_const_bufs;
        round_const_bufs.reserve(64);  // log2(k) << 64 always.

        while (n > 1) {
            uint32_t pairs = static_cast<uint32_t>(n / 2);
            uint32_t carry = static_cast<uint32_t>(n & 1u);
            id<MTLBuffer> bPairs = buf_data(&pairs, sizeof(pairs));
            id<MTLBuffer> bCarry = buf_data(&carry, sizeof(carry));
            round_const_bufs.push_back(bPairs);
            round_const_bufs.push_back(bCarry);
            size_t threads = pairs + carry;
            encode_dispatch(enc, ctx->reduce,
                            { round_in, round_out, bPairs, bCarry },
                            threads);
            // Swap.
            id<MTLBuffer> tmp = round_in;
            round_in  = round_out;
            round_out = tmp;
            n = pairs + carry;
        }

        [enc endEncoding];
        [cb commit];
        [cb waitUntilCompleted];

        // After the loop, round_in.contents[0..575] is the product.
        std::memcpy(fp12_out, [round_in contents], kFp12Bytes);
    }
    return 0;
}

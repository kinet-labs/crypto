// CUDA host driver for the combined-pair Miller-loop pack.
// Peer of bls/gpu/metal/bls_combined_miller_driver.mm.
//
// Reuses the same per-bit Miller kernels (k_miller_init, k_miller_add_T_and_line,
// k_miller_dbl_T_and_line, k_miller_sqr_ret, k_miller_fold_line, k_miller_finalize)
// in bls_miller.cu and adds the canonical pairwise tree-reduce kernel
// k_combined_miller_reduce from bls_combined_miller.cu.
//
// Build modes:
//   - BLS_HAVE_CUDA defined  : real CUDA path (CI runner with GPU).
//   - BLS_HAVE_CUDA undefined: stub returns -2 ("CUDA unavailable").

#include "bls_combined_miller_driver.h"

#include <cstdint>
#include <cstring>
#include <vector>

#ifdef BLS_HAVE_CUDA
#include <cuda_runtime.h>

extern "C" {
__global__ void k_miller_init(const void*, void*, void*, void*, unsigned);
__global__ void k_miller_add_T_and_line(const void*, void*, void*, const void*, unsigned);
__global__ void k_miller_dbl_T_and_line(void*, void*, const void*, unsigned);
__global__ void k_miller_sqr_ret(void*, unsigned);
__global__ void k_miller_fold_line(void*, const void*, unsigned);
__global__ void k_miller_finalize(void*, void*, unsigned);
__global__ void k_combined_miller_reduce(const void*, void*, unsigned, unsigned);
}

namespace {

constexpr size_t kP1Aff     = 96;
constexpr size_t kP2Aff     = 192;
constexpr size_t kInRow     = kP2Aff + kP1Aff;
constexpr size_t kP2Bytes   = 288;
constexpr size_t kFp2Bytes  = 96;
constexpr size_t kFp12Bytes = 576;
constexpr size_t kLineBytes = 3 * kFp2Bytes;

inline unsigned ceil_div(unsigned n, unsigned d) { return (n + d - 1) / d; }

int device_present()
{
    int n = 0;
    cudaError_t e = cudaGetDeviceCount(&n);
    return (e == cudaSuccess && n > 0) ? 1 : 0;
}

}  // namespace

extern "C" int bls_combined_miller_cuda_available(void)
{
    return device_present();
}

extern "C" int bls_combined_miller_cuda(const uint8_t* g1s,
                                         const uint8_t* g2s,
                                         size_t         k,
                                         uint8_t        fp12_out[576])
{
    if (fp12_out == nullptr) return -1;
    if (k == 0) return -1;
    if (g1s == nullptr || g2s == nullptr) return -1;
    if (!device_present()) return -2;

    // Pack into MillerIn layout: Q || P per workitem.
    std::vector<uint8_t> in_packed(k * kInRow);
    for (size_t i = 0; i < k; ++i) {
        std::memcpy(in_packed.data() + i * kInRow,
                    g2s + i * kP2Aff, kP2Aff);
        std::memcpy(in_packed.data() + i * kInRow + kP2Aff,
                    g1s + i * kP1Aff, kP1Aff);
    }

    void *dIn=nullptr, *dT=nullptr, *dRet=nullptr, *dPx2=nullptr;
    void *dLine=nullptr, *dMOut=nullptr, *dRed=nullptr;

    auto cleanup = [&]() {
        if (dIn)   cudaFree(dIn);
        if (dT)    cudaFree(dT);
        if (dRet)  cudaFree(dRet);
        if (dPx2)  cudaFree(dPx2);
        if (dLine) cudaFree(dLine);
        if (dMOut) cudaFree(dMOut);
        if (dRed)  cudaFree(dRed);
    };

    auto alloc = [&](void** p, size_t b) {
        return cudaMalloc(p, b) == cudaSuccess;
    };

    if (!alloc(&dIn,   k * kInRow)     ||
        !alloc(&dT,    k * kP2Bytes)   ||
        !alloc(&dRet,  k * kFp12Bytes) ||
        !alloc(&dPx2,  k * kFp2Bytes)  ||
        !alloc(&dLine, k * kLineBytes) ||
        !alloc(&dMOut, k * kFp12Bytes) ||
        !alloc(&dRed,  k * kFp12Bytes)) {
        cleanup();
        return -2;
    }

    if (cudaMemcpy(dIn, in_packed.data(), k * kInRow,
                   cudaMemcpyHostToDevice) != cudaSuccess) {
        cleanup();
        return -2;
    }

    const unsigned tg = 16;
    unsigned grid = ceil_div(static_cast<unsigned>(k), tg);
    const unsigned phases[5] = { 2u, 3u, 9u, 32u, 16u };

    // Miller loop on N=k workitems.  Each kernel is one bit of the ate
    // scalar; per-pair state stays resident in dT/dRet/dLine.
    k_miller_init<<<grid, tg>>>(dIn, dT, dRet, dPx2, static_cast<unsigned>(k));
    for (int phase = 0; phase < 5; ++phase) {
        k_miller_add_T_and_line<<<grid, tg>>>(dIn, dT, dLine, dPx2,
                                              static_cast<unsigned>(k));
        k_miller_fold_line<<<grid, tg>>>(dRet, dLine,
                                         static_cast<unsigned>(k));
        for (unsigned r = 0; r < phases[phase]; ++r) {
            k_miller_sqr_ret<<<grid, tg>>>(dRet, static_cast<unsigned>(k));
            k_miller_dbl_T_and_line<<<grid, tg>>>(dT, dLine, dPx2,
                                                  static_cast<unsigned>(k));
            k_miller_fold_line<<<grid, tg>>>(dRet, dLine,
                                             static_cast<unsigned>(k));
        }
    }
    k_miller_finalize<<<grid, tg>>>(dRet, dMOut, static_cast<unsigned>(k));

    // Canonical Fp12 tree reduction over the k outputs.
    void* round_in  = dMOut;
    void* round_out = dRed;
    size_t n = k;
    while (n > 1) {
        unsigned pairs = static_cast<unsigned>(n / 2);
        unsigned carry = static_cast<unsigned>(n & 1u);
        unsigned threads = pairs + carry;
        unsigned r_grid = ceil_div(threads, tg);
        k_combined_miller_reduce<<<r_grid, tg>>>(round_in, round_out,
                                                  pairs, carry);
        void* tmp = round_in;
        round_in  = round_out;
        round_out = tmp;
        n = pairs + carry;
    }

    cudaError_t syncErr = cudaDeviceSynchronize();
    if (syncErr != cudaSuccess) {
        cleanup();
        return -2;
    }

    // round_in points at the buffer holding the final Fp12 product at slot 0.
    if (cudaMemcpy(fp12_out, round_in, kFp12Bytes,
                   cudaMemcpyDeviceToHost) != cudaSuccess) {
        cleanup();
        return -2;
    }

    cleanup();
    return 0;
}

#else  // BLS_HAVE_CUDA undefined — stub mode.

extern "C" int bls_combined_miller_cuda_available(void) { return 0; }

extern "C" int bls_combined_miller_cuda(const uint8_t*, const uint8_t*,
                                        size_t, uint8_t[576]) {
    return -2;
}

#endif  // BLS_HAVE_CUDA

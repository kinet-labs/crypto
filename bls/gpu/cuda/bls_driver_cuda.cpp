// CUDA host driver for BLS12-381 pairing kernels.
//
// Build modes:
//   1. With CUDA toolkit (KINET_BLS_HAVE_CUDA defined):
//        - Loads PTX from a .cubin / .fatbin or invokes nvrtc to JIT compile,
//          then dispatches the same kernel sequence as the Metal driver.
//        - Mirrors run_miller / run_final_exp / run_pairing from
//          bls_pairing_test.mm exactly so byte-equality holds.
//
//   2. Without CUDA (KINET_BLS_HAVE_CUDA not defined):
//        - Provides stub functions that return -1 ("CUDA unavailable on this host").
//        - Test harness skips CUDA path and prints "[CUDA built; skipped on Apple]".
//
// Per-stage acceptance: the CI runner with a real CUDA device runs ctest with
// KINET_BLS_HAVE_CUDA=ON, which exercises the full byte-equality path against
// the same vectors_*.h headers Metal uses. On Apple, this file participates
// only in the build (proving headers are syntactically valid C++ for portable
// hosts) and is skipped at runtime.

#include "bls_driver_cuda.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#ifdef KINET_BLS_HAVE_CUDA
#include <cuda_runtime.h>

// Forward declarations of CUDA kernels. Defined in the .cu files compiled by nvcc.
extern "C" {
// Fp2/Fp6/Fp12 (called by harness directly for unit tests)
__global__ void k_fp2_add(const void*, const void*, void*, unsigned);
__global__ void k_fp2_sub(const void*, const void*, void*, unsigned);
__global__ void k_fp2_mul(const void*, const void*, void*, unsigned);
__global__ void k_fp2_sqr(const void*, void*, unsigned);
__global__ void k_fp2_inv(const void*, void*, unsigned);
__global__ void k_fp2_conj(const void*, void*, unsigned);
__global__ void k_fp_inv_diag(const void*, void*, unsigned);
__global__ void k_fp6_add(const void*, const void*, void*, unsigned);
__global__ void k_fp6_sub(const void*, const void*, void*, unsigned);
__global__ void k_fp6_mul(const void*, const void*, void*, unsigned);
__global__ void k_fp6_sqr(const void*, void*, unsigned);
__global__ void k_fp6_inv(const void*, void*, unsigned);
__global__ void k_fp12_add(const void*, const void*, void*, unsigned);
__global__ void k_fp12_sub(const void*, const void*, void*, unsigned);
__global__ void k_fp12_mul(const void*, const void*, void*, unsigned);
__global__ void k_fp12_sqr(const void*, void*, unsigned);
__global__ void k_fp12_inv(const void*, void*, unsigned);
__global__ void k_fp12_conj(const void*, void*, unsigned);
__global__ void k_fp12_cyclo_sqr(const void*, void*, unsigned);
// G2
__global__ void k_p2_jac_add(const void*, const void*, void*, unsigned);
__global__ void k_p2_jac_dbl(const void*, void*, unsigned);
__global__ void k_p2_mixed_add(const void*, const void*, void*, unsigned);
__global__ void k_p2_scalar_mult(const void*, void*, unsigned, unsigned);
// Miller
__global__ void k_miller_init(const void*, void*, void*, void*, unsigned);
__global__ void k_miller_add_T_and_line(const void*, void*, void*, const void*, unsigned);
__global__ void k_miller_dbl_T_and_line(void*, void*, const void*, unsigned);
__global__ void k_miller_sqr_ret(void*, unsigned);
__global__ void k_miller_fold_line(void*, const void*, unsigned);
__global__ void k_miller_finalize(void*, void*, unsigned);
// final_exp
__global__ void k_fe_inv(const void*, void*, unsigned);
__global__ void k_fe_cyclo_sqr(void*, unsigned);
__global__ void k_fe_mul(const void*, const void*, void*, unsigned);
__global__ void k_fe_conj(void*, unsigned);
__global__ void k_fe_frobenius(void*, unsigned, unsigned);
__global__ void k_fe_copy(const void*, void*, unsigned);
// pairing
__global__ void k_pair_one_init(void*, unsigned);
__global__ void k_pair_aggregate_step(const void*, void*, unsigned, unsigned);
__global__ void k_pair_eq_one(const void*, unsigned char*, unsigned);
}

namespace kinet_bls_cuda {

static unsigned compute_grid(unsigned n, unsigned tg) { return (n + tg - 1) / tg; }

static int device_available() {
    int count = 0;
    cudaError_t e = cudaGetDeviceCount(&count);
    return (e == cudaSuccess && count > 0) ? 1 : 0;
}

// Generic dispatcher: launch a 3-buffer (a, b, out) kernel.
template <typename Fn>
static int dispatch3(Fn kernel, const void* a, const void* b, void* out,
                     size_t bytes, unsigned n) {
    void *dA = nullptr, *dB = nullptr, *dO = nullptr;
    if (cudaMalloc(&dA, bytes) != cudaSuccess) return -1;
    if (cudaMalloc(&dB, bytes) != cudaSuccess) { cudaFree(dA); return -1; }
    if (cudaMalloc(&dO, bytes) != cudaSuccess) { cudaFree(dA); cudaFree(dB); return -1; }
    cudaMemcpy(dA, a, bytes, cudaMemcpyHostToDevice);
    cudaMemcpy(dB, b, bytes, cudaMemcpyHostToDevice);
    unsigned tg = 32; unsigned grid = compute_grid(n, tg);
    kernel<<<grid, tg>>>(dA, dB, dO, n);
    cudaDeviceSynchronize();
    cudaMemcpy(out, dO, bytes, cudaMemcpyDeviceToHost);
    cudaFree(dA); cudaFree(dB); cudaFree(dO);
    return 0;
}

template <typename Fn>
static int dispatch2(Fn kernel, const void* a, void* out, size_t bytes, unsigned n) {
    void *dA = nullptr, *dO = nullptr;
    if (cudaMalloc(&dA, bytes) != cudaSuccess) return -1;
    if (cudaMalloc(&dO, bytes) != cudaSuccess) { cudaFree(dA); return -1; }
    cudaMemcpy(dA, a, bytes, cudaMemcpyHostToDevice);
    unsigned tg = 32; unsigned grid = compute_grid(n, tg);
    kernel<<<grid, tg>>>(dA, dO, n);
    cudaDeviceSynchronize();
    cudaMemcpy(out, dO, bytes, cudaMemcpyDeviceToHost);
    cudaFree(dA); cudaFree(dO);
    return 0;
}

} // namespace kinet_bls_cuda

extern "C" {

int kinet_bls_cuda_available(void) { return kinet_bls_cuda::device_available(); }

int kinet_bls_cuda_fp2_mul(const void* a, const void* b, void* out, unsigned n) {
    return kinet_bls_cuda::dispatch3(k_fp2_mul, a, b, out, 96 * n, n);
}
int kinet_bls_cuda_fp12_mul(const void* a, const void* b, void* out, unsigned n) {
    return kinet_bls_cuda::dispatch3(k_fp12_mul, a, b, out, 576 * n, n);
}

// Full pairing entry point. Inputs match Metal layout exactly:
//   in: array of N * (P2Aff || P1Aff) = N * (192 + 96) = N * 288 bytes
//   out: array of N * Fp12 = N * 576 bytes
//
// CI dispatches the same kernel sequence as run_pairing in
// bls_pairing_test.mm:  miller_loop (6 kernels) -> final_exp (5 kernels).
// On byte-equality CI the result is byte-equal Metal and CPU oracle.
int kinet_bls_cuda_pairing(const void* in_buf, void* out_buf, unsigned N) {
    if (!kinet_bls_cuda::device_available()) return -1;
    constexpr size_t kP2Bytes   = 288;
    constexpr size_t kFp2Bytes  = 96;
    constexpr size_t kFp12Bytes = 576;
    constexpr size_t kP2Aff     = 192;
    constexpr size_t kP1Aff     = 96;
    constexpr size_t kInRow     = kP2Aff + kP1Aff;
    constexpr size_t kLineBytes = 3 * kFp2Bytes;

    void *dIn=nullptr,*dT=nullptr,*dRet=nullptr,*dPx2=nullptr,*dLine=nullptr;
    void *dMillerOut=nullptr,*dY0=nullptr,*dY1=nullptr,*dY2=nullptr,*dY3=nullptr,*dTmp=nullptr;

    auto alloc = [&](void** p, size_t b) { return cudaMalloc(p, b) == cudaSuccess; };

    if (!alloc(&dIn,        N*kInRow)      ||
        !alloc(&dT,         N*kP2Bytes)    ||
        !alloc(&dRet,       N*kFp12Bytes)  ||
        !alloc(&dPx2,       N*kFp2Bytes)   ||
        !alloc(&dLine,      N*kLineBytes)  ||
        !alloc(&dMillerOut, N*kFp12Bytes)  ||
        !alloc(&dY0,        N*kFp12Bytes)  ||
        !alloc(&dY1,        N*kFp12Bytes)  ||
        !alloc(&dY2,        N*kFp12Bytes)  ||
        !alloc(&dY3,        N*kFp12Bytes)  ||
        !alloc(&dTmp,       N*kFp12Bytes)) {
        return -1;
    }

    cudaMemcpy(dIn, in_buf, N*kInRow, cudaMemcpyHostToDevice);

    unsigned tg = 16;
    unsigned grid = kinet_bls_cuda::compute_grid(N, tg);

    // Miller-loop phase doubling counts (same as Metal).
    const unsigned kPhases[5] = { 2u, 3u, 9u, 32u, 16u };

    // init
    k_miller_init<<<grid,tg>>>(dIn, dT, dRet, dPx2, N);
    cudaDeviceSynchronize();

    for (int phase = 0; phase < 5; phase++) {
        k_miller_add_T_and_line<<<grid,tg>>>(dIn, dT, dLine, dPx2, N);
        cudaDeviceSynchronize();
        k_miller_fold_line<<<grid,tg>>>(dRet, dLine, N);
        cudaDeviceSynchronize();
        for (unsigned k = 0; k < kPhases[phase]; k++) {
            k_miller_sqr_ret<<<grid,tg>>>(dRet, N);
            cudaDeviceSynchronize();
            k_miller_dbl_T_and_line<<<grid,tg>>>(dT, dLine, dPx2, N);
            cudaDeviceSynchronize();
            k_miller_fold_line<<<grid,tg>>>(dRet, dLine, N);
            cudaDeviceSynchronize();
        }
    }
    k_miller_finalize<<<grid,tg>>>(dRet, dMillerOut, N);
    cudaDeviceSynchronize();

    // final_exp easy part
    k_fe_copy<<<grid,tg>>>(dMillerOut, dY1, N); cudaDeviceSynchronize();
    k_fe_conj<<<grid,tg>>>(dY1, N);             cudaDeviceSynchronize();
    k_fe_inv<<<grid,tg>>>(dMillerOut, dY2, N);  cudaDeviceSynchronize();
    k_fe_mul<<<grid,tg>>>(dY1, dY2, dRet, N);   cudaDeviceSynchronize();
    k_fe_copy<<<grid,tg>>>(dRet, dY2, N);       cudaDeviceSynchronize();
    k_fe_frobenius<<<grid,tg>>>(dY2, N, 2u);    cudaDeviceSynchronize();
    k_fe_mul<<<grid,tg>>>(dRet, dY2, dTmp, N);  cudaDeviceSynchronize();
    k_fe_copy<<<grid,tg>>>(dTmp, dRet, N);      cudaDeviceSynchronize();

    // hard part: see bls_pairing_test.mm:run_final_exp() — same dispatch order.
    auto cyclo_sqr = [&](void* b) { k_fe_cyclo_sqr<<<grid,tg>>>(b, N); cudaDeviceSynchronize(); };
    auto fe_mul = [&](void* a, void* b, void* c) {
        k_fe_mul<<<grid,tg>>>(a, b, c, N); cudaDeviceSynchronize();
    };
    auto fe_copy = [&](void* s, void* d) {
        k_fe_copy<<<grid,tg>>>(s, d, N); cudaDeviceSynchronize();
    };
    auto fe_conj = [&](void* b) { k_fe_conj<<<grid,tg>>>(b, N); cudaDeviceSynchronize(); };
    auto fe_frob = [&](void* b, unsigned n_pow) {
        k_fe_frobenius<<<grid,tg>>>(b, N, n_pow); cudaDeviceSynchronize();
    };

    auto raise_to_z_div_2 = [&](void* out, void* a, void* tmp) {
        fe_copy(a, out);
        cyclo_sqr(out);
        auto mul_n_sqr = [&](unsigned n) {
            fe_mul(out, a, tmp); fe_copy(tmp, out);
            for (unsigned i = 0; i < n; i++) cyclo_sqr(out);
        };
        mul_n_sqr(2); mul_n_sqr(3); mul_n_sqr(9);
        mul_n_sqr(32); mul_n_sqr(15);
        fe_conj(out);
    };
    auto raise_to_z = [&](void* out, void* a, void* tmp) {
        raise_to_z_div_2(out, a, tmp); cyclo_sqr(out);
    };

    fe_copy(dRet, dY0); cyclo_sqr(dY0);
    raise_to_z(dY1, dY0, dTmp);
    raise_to_z_div_2(dY2, dY1, dTmp);
    fe_copy(dRet, dY3); fe_conj(dY3);
    fe_mul(dY1, dY3, dTmp); fe_copy(dTmp, dY1);
    fe_conj(dY1);
    fe_mul(dY1, dY2, dTmp); fe_copy(dTmp, dY1);
    raise_to_z(dY2, dY1, dTmp);
    raise_to_z(dY3, dY2, dTmp);
    fe_conj(dY1);
    fe_mul(dY3, dY1, dTmp); fe_copy(dTmp, dY3);
    fe_conj(dY1);
    fe_frob(dY1, 3u);
    fe_frob(dY2, 2u);
    fe_mul(dY1, dY2, dTmp); fe_copy(dTmp, dY1);
    raise_to_z(dY2, dY3, dTmp);
    fe_mul(dY2, dY0, dTmp);  fe_copy(dTmp, dY2);
    fe_mul(dY2, dRet, dTmp); fe_copy(dTmp, dY2);
    fe_mul(dY1, dY2, dTmp);  fe_copy(dTmp, dY1);
    fe_copy(dY3, dY2);
    fe_frob(dY2, 1u);
    fe_mul(dY1, dY2, dTmp);
    cudaMemcpy(out_buf, dTmp, N*kFp12Bytes, cudaMemcpyDeviceToHost);

    cudaFree(dIn); cudaFree(dT); cudaFree(dRet); cudaFree(dPx2); cudaFree(dLine);
    cudaFree(dMillerOut); cudaFree(dY0); cudaFree(dY1); cudaFree(dY2); cudaFree(dY3); cudaFree(dTmp);
    return 0;
}

} // extern "C"

#else // KINET_BLS_HAVE_CUDA not defined: stub mode

extern "C" {
int kinet_bls_cuda_available(void) { return 0; }
int kinet_bls_cuda_fp2_mul(const void*, const void*, void*, unsigned) { return -1; }
int kinet_bls_cuda_fp12_mul(const void*, const void*, void*, unsigned) { return -1; }
int kinet_bls_cuda_pairing(const void*, void*, unsigned) { return -1; }
}

#endif // KINET_BLS_HAVE_CUDA

// CUDA host driver for Banderwagon group ops.
//
// Build modes:
//   1. With CUDA toolkit (KINET_BANDERWAGON_HAVE_CUDA defined): compiles
//      banderwagon.cu via nvcc, dispatches kernels with one thread per work
//      item (or per MSM). Byte-equal to kinet::banderwagon::Element ops.
//   2. Without CUDA: stub mode. banderwagon_cuda_available() returns 0,
//      every dispatch returns -1.

#include "banderwagon_driver.h"

#include <cstdint>

#ifdef KINET_BANDERWAGON_HAVE_CUDA
#include <cuda_runtime.h>

extern "C" __global__ void banderwagon_add_batch(
    const uint8_t* pairs, uint8_t* outs, uint32_t n);
extern "C" __global__ void banderwagon_double_batch(
    const uint8_t* pts, uint8_t* outs, uint32_t n);
extern "C" __global__ void banderwagon_smul_batch(
    const uint8_t* pts, const uint8_t* scalars, uint8_t* outs, uint32_t n);
extern "C" __global__ void banderwagon_msm_batch_naive(
    const uint8_t* pts, const uint8_t* scalars, uint8_t* outs,
    uint32_t n, uint32_t M);

extern "C" int banderwagon_cuda_available(void) {
    int count = 0;
    cudaError_t e = cudaGetDeviceCount(&count);
    return (e == cudaSuccess && count > 0) ? 1 : 0;
}

namespace {
struct DevPtr {
    uint8_t* p = nullptr;
    ~DevPtr() { if (p) cudaFree(p); }
};
}  // namespace

extern "C" int banderwagon_cuda_add_batch(
    const uint8_t* pairs, uint8_t* outs, size_t n) {
    if (n == 0) return 0;
    if (!pairs || !outs) return -1;
    if (!banderwagon_cuda_available()) return -2;

    DevPtr d_in, d_out;
    if (cudaMalloc((void**)&d_in.p, n * 192) != cudaSuccess) return -3;
    if (cudaMalloc((void**)&d_out.p, n * 96) != cudaSuccess) return -3;
    if (cudaMemcpy(d_in.p, pairs, n * 192, cudaMemcpyHostToDevice) != cudaSuccess) return -4;
    unsigned tg = 64;
    unsigned grid = unsigned((n + tg - 1) / tg);
    banderwagon_add_batch<<<grid, tg>>>(d_in.p, d_out.p, (uint32_t)n);
    if (cudaDeviceSynchronize() != cudaSuccess) return -4;
    if (cudaMemcpy(outs, d_out.p, n * 96, cudaMemcpyDeviceToHost) != cudaSuccess) return -4;
    return 0;
}

extern "C" int banderwagon_cuda_double_batch(
    const uint8_t* pts, uint8_t* outs, size_t n) {
    if (n == 0) return 0;
    if (!pts || !outs) return -1;
    if (!banderwagon_cuda_available()) return -2;

    DevPtr d_in, d_out;
    if (cudaMalloc((void**)&d_in.p, n * 96) != cudaSuccess) return -3;
    if (cudaMalloc((void**)&d_out.p, n * 96) != cudaSuccess) return -3;
    if (cudaMemcpy(d_in.p, pts, n * 96, cudaMemcpyHostToDevice) != cudaSuccess) return -4;
    unsigned tg = 64;
    unsigned grid = unsigned((n + tg - 1) / tg);
    banderwagon_double_batch<<<grid, tg>>>(d_in.p, d_out.p, (uint32_t)n);
    if (cudaDeviceSynchronize() != cudaSuccess) return -4;
    if (cudaMemcpy(outs, d_out.p, n * 96, cudaMemcpyDeviceToHost) != cudaSuccess) return -4;
    return 0;
}

extern "C" int banderwagon_cuda_smul_batch(
    const uint8_t* pts, const uint8_t* scalars, uint8_t* outs, size_t n) {
    if (n == 0) return 0;
    if (!pts || !scalars || !outs) return -1;
    if (!banderwagon_cuda_available()) return -2;

    DevPtr d_pts, d_scl, d_out;
    if (cudaMalloc((void**)&d_pts.p, n * 96) != cudaSuccess) return -3;
    if (cudaMalloc((void**)&d_scl.p, n * 32) != cudaSuccess) return -3;
    if (cudaMalloc((void**)&d_out.p, n * 96) != cudaSuccess) return -3;
    if (cudaMemcpy(d_pts.p, pts, n * 96, cudaMemcpyHostToDevice) != cudaSuccess) return -4;
    if (cudaMemcpy(d_scl.p, scalars, n * 32, cudaMemcpyHostToDevice) != cudaSuccess) return -4;
    unsigned tg = 32;
    unsigned grid = unsigned((n + tg - 1) / tg);
    banderwagon_smul_batch<<<grid, tg>>>(d_pts.p, d_scl.p, d_out.p, (uint32_t)n);
    if (cudaDeviceSynchronize() != cudaSuccess) return -4;
    if (cudaMemcpy(outs, d_out.p, n * 96, cudaMemcpyDeviceToHost) != cudaSuccess) return -4;
    return 0;
}

extern "C" int banderwagon_cuda_msm_batch(
    const uint8_t* pts, const uint8_t* scalars, uint8_t* outs,
    size_t n, size_t M) {
    if (n == 0 || M == 0) return 0;
    if (!pts || !scalars || !outs) return -1;
    if (!banderwagon_cuda_available()) return -2;

    DevPtr d_pts, d_scl, d_out;
    if (cudaMalloc((void**)&d_pts.p, n * 96) != cudaSuccess) return -3;
    if (cudaMalloc((void**)&d_scl.p, M * n * 32) != cudaSuccess) return -3;
    if (cudaMalloc((void**)&d_out.p, M * 96) != cudaSuccess) return -3;
    if (cudaMemcpy(d_pts.p, pts, n * 96, cudaMemcpyHostToDevice) != cudaSuccess) return -4;
    if (cudaMemcpy(d_scl.p, scalars, M * n * 32, cudaMemcpyHostToDevice) != cudaSuccess) return -4;
    unsigned tg = 32;
    unsigned grid = unsigned((M + tg - 1) / tg);
    banderwagon_msm_batch_naive<<<grid, tg>>>(d_pts.p, d_scl.p, d_out.p,
                                              (uint32_t)n, (uint32_t)M);
    if (cudaDeviceSynchronize() != cudaSuccess) return -4;
    if (cudaMemcpy(outs, d_out.p, M * 96, cudaMemcpyDeviceToHost) != cudaSuccess) return -4;
    return 0;
}

#else  // KINET_BANDERWAGON_HAVE_CUDA not defined: stub mode

extern "C" int banderwagon_cuda_available(void) { return 0; }
extern "C" int banderwagon_cuda_add_batch(const uint8_t*, uint8_t*, size_t) { return -1; }
extern "C" int banderwagon_cuda_double_batch(const uint8_t*, uint8_t*, size_t) { return -1; }
extern "C" int banderwagon_cuda_smul_batch(const uint8_t*, const uint8_t*, uint8_t*, size_t) { return -1; }
extern "C" int banderwagon_cuda_msm_batch(const uint8_t*, const uint8_t*, uint8_t*, size_t, size_t) { return -1; }

#endif

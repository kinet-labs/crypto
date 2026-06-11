// CUDA host driver for the batched Pedersen vector commitment.
//
// Build modes:
//   1. With CUDA toolkit (KINET_PEDERSEN_HAVE_CUDA defined):
//        - Allocates device buffers, copies wire-format inputs, launches
//          k_pedersen_pointmul + k_pedersen_reduce_add (defined in
//          pedersen.cu), copies the M*64 output back.
//        - Byte-equal to pedersen_batch_metal and the Go canonical at
//          github.com/kinet-labs/crypto/pedersen.
//   2. Without CUDA: returns -1 (non-zero) and kinet_pedersen_cuda_available()
//      returns 0, so test harnesses skip the CUDA path.

#include "pedersen_driver_cuda.h"

#include <cstdint>
#include <cstring>

#ifdef KINET_PEDERSEN_HAVE_CUDA
#include <cuda_runtime.h>

struct PedersenDimsHost { uint32_t M; uint32_t N; };

extern "C" __global__ void k_pedersen_pointmul(
    const uint8_t*, const uint8_t*, const uint8_t*,
    uint64_t*, PedersenDimsHost);
extern "C" __global__ void k_pedersen_reduce_add(
    const uint64_t*, uint8_t*, PedersenDimsHost);

extern "C" int kinet_pedersen_cuda_available(void) {
    int count = 0;
    cudaError_t e = cudaGetDeviceCount(&count);
    return (e == cudaSuccess && count > 0) ? 1 : 0;
}

extern "C" int pedersen_batch_cuda(
    const uint8_t* gens_be,
    const uint8_t* scalars_be,
    const uint8_t* blindings_be,
    uint32_t       M,
    uint32_t       N,
    uint8_t*       out_be) {
    if (M == 0 || N == 0) return 0;
    if (!gens_be || !scalars_be || !blindings_be || !out_be) return -1;
    if (!kinet_pedersen_cuda_available()) return -1;

    size_t gens_len    = (size_t)(N + 1) * 64;
    size_t scalars_len = (size_t)M * N * 32;
    size_t blind_len   = (size_t)M * 32;
    size_t scratch_u64 = (size_t)M * (N + 1) * 12;
    size_t out_len     = (size_t)M * 64;

    uint8_t  *dGens=nullptr, *dScalars=nullptr, *dBlind=nullptr, *dOut=nullptr;
    uint64_t *dScratch=nullptr;

    auto cleanup = [&]() {
        if (dGens)    cudaFree(dGens);
        if (dScalars) cudaFree(dScalars);
        if (dBlind)   cudaFree(dBlind);
        if (dScratch) cudaFree(dScratch);
        if (dOut)     cudaFree(dOut);
    };

    if (cudaMalloc((void**)&dGens,    gens_len)               != cudaSuccess) { cleanup(); return -2; }
    if (cudaMalloc((void**)&dScalars, scalars_len)            != cudaSuccess) { cleanup(); return -2; }
    if (cudaMalloc((void**)&dBlind,   blind_len)              != cudaSuccess) { cleanup(); return -2; }
    if (cudaMalloc((void**)&dScratch, scratch_u64*sizeof(uint64_t)) != cudaSuccess) { cleanup(); return -2; }
    if (cudaMalloc((void**)&dOut,     out_len)                != cudaSuccess) { cleanup(); return -2; }

    cudaMemcpy(dGens,    gens_be,      gens_len,    cudaMemcpyHostToDevice);
    cudaMemcpy(dScalars, scalars_be,   scalars_len, cudaMemcpyHostToDevice);
    cudaMemcpy(dBlind,   blindings_be, blind_len,   cudaMemcpyHostToDevice);

    PedersenDimsHost dims{ M, N };

    // Stage 1: pointmul -- M*(N+1) threads.
    {
        unsigned tg = 64;
        unsigned total = M * (N + 1);
        unsigned grid = (total + tg - 1) / tg;
        k_pedersen_pointmul<<<grid, tg>>>(dGens, dScalars, dBlind, dScratch, dims);
        if (cudaDeviceSynchronize() != cudaSuccess) { cleanup(); return -3; }
    }

    // Stage 2: reduce_add -- M threads.
    {
        unsigned tg = 32;
        unsigned grid = (M + tg - 1) / tg;
        k_pedersen_reduce_add<<<grid, tg>>>(dScratch, dOut, dims);
        if (cudaDeviceSynchronize() != cudaSuccess) { cleanup(); return -4; }
    }

    cudaMemcpy(out_be, dOut, out_len, cudaMemcpyDeviceToHost);
    cleanup();
    return 0;
}

#else // KINET_PEDERSEN_HAVE_CUDA not defined: stub mode

extern "C" int kinet_pedersen_cuda_available(void) { return 0; }

extern "C" int pedersen_batch_cuda(
    const uint8_t*, const uint8_t*, const uint8_t*,
    uint32_t, uint32_t, uint8_t*) {
    return -1;
}

#endif

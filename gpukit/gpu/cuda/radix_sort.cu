// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// CUDA radix sort (LSD, 8-bit pass) -- skeleton. Compile-only on Apple host.

#include "kinet/gpukit/radix_sort.h"
#include "kinet/gpukit/gpukit.h"

#if defined(__CUDACC__) || defined(KINET_GPUKIT_HAS_CUDA)

#include <cuda_runtime.h>
#include <vector>
#include <cstring>

namespace {

template <typename T>
__global__ void count_kernel(const T* in, unsigned* hist, unsigned n, unsigned shift) {
    unsigned i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    unsigned b = (unsigned)((in[i] >> shift) & 0xFFu);
    atomicAdd(&hist[b], 1u);
}

template <typename T>
__global__ void scatter_kernel(const T* in, const unsigned* base, unsigned* cursor,
                               T* out, unsigned n, unsigned shift) {
    unsigned i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    unsigned b = (unsigned)((in[i] >> shift) & 0xFFu);
    unsigned off = atomicAdd(&cursor[b], 1u);
    out[base[b] + off] = in[i];
}

template <typename T>
int run_radix(T* keys, size_t n) {
    if (!keys) return GPUKIT_ERR_NULL_ARG;
    if (n < 2) return GPUKIT_OK;
    size_t bytes = n * sizeof(T);
    T *d_a=nullptr, *d_b=nullptr;
    unsigned *d_hist=nullptr, *d_base=nullptr, *d_cursor=nullptr;
    cudaMalloc(&d_a,      bytes);
    cudaMalloc(&d_b,      bytes);
    cudaMalloc(&d_hist,   256*sizeof(unsigned));
    cudaMalloc(&d_base,   256*sizeof(unsigned));
    cudaMalloc(&d_cursor, 256*sizeof(unsigned));
    cudaMemcpy(d_a, keys, bytes, cudaMemcpyHostToDevice);

    constexpr int PASSES = sizeof(T);
    T* src = d_a; T* dst = d_b;
    unsigned blocks = (unsigned)((n + 255) / 256);
    for (int p = 0; p < PASSES; ++p) {
        unsigned shift = (unsigned)(p * 8);
        cudaMemset(d_hist,   0, 256*sizeof(unsigned));
        count_kernel<T><<<blocks, 256>>>(src, d_hist, (unsigned)n, shift);
        // Exclusive scan on host.
        std::vector<unsigned> h(256);
        cudaMemcpy(h.data(), d_hist, 256*sizeof(unsigned), cudaMemcpyDeviceToHost);
        std::vector<unsigned> base(256);
        unsigned acc = 0;
        for (int i = 0; i < 256; ++i) { base[i] = acc; acc += h[i]; }
        cudaMemcpy(d_base, base.data(), 256*sizeof(unsigned), cudaMemcpyHostToDevice);
        cudaMemset(d_cursor, 0, 256*sizeof(unsigned));
        scatter_kernel<T><<<blocks, 256>>>(src, d_base, d_cursor, dst, (unsigned)n, shift);
        T* tmp = src; src = dst; dst = tmp;
    }
    cudaMemcpy(keys, src, bytes, cudaMemcpyDeviceToHost);
    cudaFree(d_a); cudaFree(d_b); cudaFree(d_hist); cudaFree(d_base); cudaFree(d_cursor);
    return GPUKIT_OK;
}

}  // namespace

extern "C" int gpukit_radix_sort_u32_cuda(uint32_t* keys, size_t n) { return run_radix<uint32_t>(keys, n); }
extern "C" int gpukit_radix_sort_u64_cuda(uint64_t* keys, size_t n) { return run_radix<uint64_t>(keys, n); }

#else

extern "C" int gpukit_radix_sort_u32_cuda(uint32_t*, size_t) { return GPUKIT_ERR_NOTIMPL; }
extern "C" int gpukit_radix_sort_u64_cuda(uint64_t*, size_t) { return GPUKIT_ERR_NOTIMPL; }

#endif

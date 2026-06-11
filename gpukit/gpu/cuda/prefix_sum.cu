// CUDA prefix sum (inclusive scan) -- u32 / u64.
//
// Two-stage: per-block Hillis-Steele scan, then add block-prefix on a second
// dispatch. Block size 1024.
//
// Built only when GPUKIT_ENABLE_CUDA is set; the host wrapper is in this
// translation unit and exposes gpukit_prefix_sum_{u32,u64}_cuda. On Apple
// hosts where CUDA is unavailable, a fallback symbol returns NOTIMPL (see
// prefix_sum_cuda_stub.cpp -- not built when CUDA is on).

#include "kinet/gpukit/prefix_sum.h"
#include "kinet/gpukit/gpukit.h"

#if defined(__CUDACC__) || defined(GPUKIT_HAS_CUDA)

#include <cuda_runtime.h>
#include <cstring>

#define BLOCK 1024u

namespace {

template <typename T>
__global__ void block_scan(const T* in, T* out, T* block_sums, unsigned n) {
    __shared__ T s[BLOCK];
    unsigned i = blockIdx.x * BLOCK + threadIdx.x;
    s[threadIdx.x] = (i < n) ? in[i] : T(0);
    __syncthreads();
    for (unsigned d = 1; d < BLOCK; d <<= 1) {
        T v = s[threadIdx.x];
        T w = (threadIdx.x >= d) ? s[threadIdx.x - d] : T(0);
        __syncthreads();
        s[threadIdx.x] = v + w;
        __syncthreads();
    }
    if (i < n) out[i] = s[threadIdx.x];
    if (threadIdx.x == BLOCK - 1) block_sums[blockIdx.x] = s[threadIdx.x];
}

template <typename T>
__global__ void collect(T* out, const T* prefix, unsigned n) {
    unsigned gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= n) return;
    unsigned b = gid / BLOCK;
    if (b == 0) return;
    out[gid] += prefix[b - 1];
}

template <typename T>
int run(const T* in, T* out, size_t n) {
    if (!in || !out) return GPUKIT_ERR_NULL_ARG;
    if (n == 0) return GPUKIT_OK;
    size_t bytes = n * sizeof(T);
    size_t nb = (n + BLOCK - 1) / BLOCK;
    T *d_in=nullptr, *d_out=nullptr, *d_bs=nullptr;
    if (cudaMalloc(&d_in,  bytes)        != cudaSuccess) return GPUKIT_ERR_BACKEND;
    if (cudaMalloc(&d_out, bytes)        != cudaSuccess) { cudaFree(d_in); return GPUKIT_ERR_BACKEND; }
    if (cudaMalloc(&d_bs,  nb*sizeof(T)) != cudaSuccess) { cudaFree(d_in); cudaFree(d_out); return GPUKIT_ERR_BACKEND; }
    cudaMemcpy(d_in, in, bytes, cudaMemcpyHostToDevice);
    block_scan<T><<<(unsigned)nb, BLOCK>>>(d_in, d_out, d_bs, (unsigned)n);
    if (nb > 1) {
        // Serial host scan of block sums.
        std::vector<T> bs(nb);
        cudaMemcpy(bs.data(), d_bs, nb*sizeof(T), cudaMemcpyDeviceToHost);
        for (size_t i = 1; i < nb; ++i) bs[i] += bs[i-1];
        cudaMemcpy(d_bs, bs.data(), nb*sizeof(T), cudaMemcpyHostToDevice);
        collect<T><<<(unsigned)((n+255)/256), 256>>>(d_out, d_bs, (unsigned)n);
    }
    cudaMemcpy(out, d_out, bytes, cudaMemcpyDeviceToHost);
    cudaFree(d_in); cudaFree(d_out); cudaFree(d_bs);
    return GPUKIT_OK;
}

}  // namespace

extern "C" int gpukit_prefix_sum_u32_cuda(const uint32_t* in, uint32_t* out, size_t n) {
    return run<uint32_t>(in, out, n);
}
extern "C" int gpukit_prefix_sum_u64_cuda(const uint64_t* in, uint64_t* out, size_t n) {
    return run<uint64_t>(in, out, n);
}

#else

extern "C" int gpukit_prefix_sum_u32_cuda(const uint32_t*, uint32_t*, size_t) {
    return GPUKIT_ERR_NOTIMPL;
}
extern "C" int gpukit_prefix_sum_u64_cuda(const uint64_t*, uint64_t*, size_t) {
    return GPUKIT_ERR_NOTIMPL;
}

#endif

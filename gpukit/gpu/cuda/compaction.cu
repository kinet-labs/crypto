// CUDA stream compaction. Mark + scan + scatter.

#include "kinet/gpukit/compaction.h"
#include "kinet/gpukit/prefix_sum.h"
#include "kinet/gpukit/gpukit.h"

#if defined(__CUDACC__) || defined(GPUKIT_HAS_CUDA)

#include <cuda_runtime.h>
#include <vector>
#include <cstring>

namespace {
__global__ void mark_kernel(const uint8_t* flags, unsigned* marks, unsigned n) {
    unsigned i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    marks[i] = flags[i] ? 1u : 0u;
}
__global__ void scatter_kernel(const unsigned* in, const uint8_t* flags,
                               const unsigned* scan, unsigned* out, unsigned n) {
    unsigned i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    if (!flags[i]) return;
    out[scan[i] - 1] = in[i];
}
}  // namespace

extern "C" int gpukit_compact_u32_cuda(const uint32_t* in, const uint8_t* flags,
                                       uint32_t* out, size_t n, size_t* n_out) {
    if (!in || !flags || !out || !n_out) return GPUKIT_ERR_NULL_ARG;
    if (n == 0) { *n_out = 0; return GPUKIT_OK; }
    size_t bytes = n * sizeof(uint32_t);
    uint32_t *d_in=nullptr, *d_marks=nullptr, *d_scan=nullptr, *d_out=nullptr;
    uint8_t  *d_flags=nullptr;
    cudaMalloc(&d_in,    bytes);
    cudaMalloc(&d_marks, bytes);
    cudaMalloc(&d_scan,  bytes);
    cudaMalloc(&d_out,   bytes);
    cudaMalloc(&d_flags, n);
    cudaMemcpy(d_in,    in,    bytes, cudaMemcpyHostToDevice);
    cudaMemcpy(d_flags, flags, n,     cudaMemcpyHostToDevice);

    unsigned blocks = (unsigned)((n + 255) / 256);
    mark_kernel<<<blocks, 256>>>(d_flags, d_marks, (unsigned)n);

    // Run scan on host (use the CPU reference -- byte-equal target).
    std::vector<uint32_t> marks_h(n);
    cudaMemcpy(marks_h.data(), d_marks, bytes, cudaMemcpyDeviceToHost);
    gpukit_prefix_sum_u32_cpu(marks_h.data(), marks_h.data(), n);
    cudaMemcpy(d_scan, marks_h.data(), bytes, cudaMemcpyHostToDevice);

    scatter_kernel<<<blocks, 256>>>(d_in, d_flags, d_scan, d_out, (unsigned)n);
    size_t k = marks_h[n-1];
    cudaMemcpy(out, d_out, k * sizeof(uint32_t), cudaMemcpyDeviceToHost);
    *n_out = k;
    cudaFree(d_in); cudaFree(d_marks); cudaFree(d_scan); cudaFree(d_out); cudaFree(d_flags);
    return GPUKIT_OK;
}

#else

extern "C" int gpukit_compact_u32_cuda(const uint32_t*, const uint8_t*, uint32_t*, size_t, size_t*) {
    return GPUKIT_ERR_NOTIMPL;
}

#endif

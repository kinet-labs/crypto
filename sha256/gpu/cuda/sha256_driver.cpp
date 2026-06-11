// CUDA host driver for batched SHA-256 (FIPS 180-4).
//
// Build modes:
//   1. With CUDA toolkit (KINET_SHA256_HAVE_CUDA defined):
//        - Compiles sha256.cu via nvcc; invokes the kernel with one thread
//          per input. Byte-equal to sha256/cpp/sha256.cpp::sha256() and to
//          sha256/gpu/metal/sha256_batch.metal.
//   2. Without CUDA (KINET_SHA256_HAVE_CUDA not defined):
//        - Stub mode: kinet_sha256_cuda_available() returns 0, every other
//          function returns -1 ("CUDA unavailable on this host"). The test
//          harness skips the CUDA path on Apple/non-CUDA hosts.

#include "sha256_driver.h"

#include <cstdint>
#include <cstring>

#ifdef KINET_SHA256_HAVE_CUDA
#include <cuda_runtime.h>

// Forward declaration of the CUDA kernel defined in sha256.cu.
extern "C" __global__ void sha256_jobs(
    const uint8_t*  inputs,
    const uint32_t* input_offsets,
    const uint32_t* input_lens,
    uint8_t*        outputs,
    uint32_t        num_jobs);

extern "C" int kinet_sha256_cuda_available(void) {
    int count = 0;
    cudaError_t e = cudaGetDeviceCount(&count);
    return (e == cudaSuccess && count > 0) ? 1 : 0;
}

extern "C" int sha256_batch_cuda(
    const uint8_t*  inputs_arena,
    size_t          inputs_arena_len,
    const uint32_t* input_offsets,
    const uint32_t* input_lens,
    size_t          n,
    uint8_t*        outputs_arena) {

    if (n == 0) return 0;
    if (!inputs_arena || !input_offsets || !input_lens || !outputs_arena) return -1;
    if (!kinet_sha256_cuda_available()) return -2;

    uint8_t*  d_inputs  = nullptr;
    uint32_t* d_offsets = nullptr;
    uint32_t* d_lens    = nullptr;
    uint8_t*  d_outputs = nullptr;
    size_t out_bytes = n * 32u;

    auto cleanup = [&]() {
        if (d_inputs)  cudaFree(d_inputs);
        if (d_offsets) cudaFree(d_offsets);
        if (d_lens)    cudaFree(d_lens);
        if (d_outputs) cudaFree(d_outputs);
    };

    if (cudaMalloc((void**)&d_inputs,  inputs_arena_len ? inputs_arena_len : 1) != cudaSuccess) {
        cleanup(); return -3;
    }
    if (cudaMalloc((void**)&d_offsets, n * sizeof(uint32_t)) != cudaSuccess) {
        cleanup(); return -3;
    }
    if (cudaMalloc((void**)&d_lens,    n * sizeof(uint32_t)) != cudaSuccess) {
        cleanup(); return -3;
    }
    if (cudaMalloc((void**)&d_outputs, out_bytes) != cudaSuccess) {
        cleanup(); return -3;
    }

    if (inputs_arena_len) {
        if (cudaMemcpy(d_inputs, inputs_arena, inputs_arena_len,
                       cudaMemcpyHostToDevice) != cudaSuccess) {
            cleanup(); return -4;
        }
    }
    if (cudaMemcpy(d_offsets, input_offsets, n * sizeof(uint32_t),
                   cudaMemcpyHostToDevice) != cudaSuccess) {
        cleanup(); return -4;
    }
    if (cudaMemcpy(d_lens, input_lens, n * sizeof(uint32_t),
                   cudaMemcpyHostToDevice) != cudaSuccess) {
        cleanup(); return -4;
    }

    unsigned tg   = 64;
    unsigned grid = unsigned((n + tg - 1) / tg);
    sha256_jobs<<<grid, tg>>>(d_inputs, d_offsets, d_lens,
                              d_outputs, uint32_t(n));
    if (cudaDeviceSynchronize() != cudaSuccess) {
        cleanup(); return -4;
    }
    if (cudaMemcpy(outputs_arena, d_outputs, out_bytes,
                   cudaMemcpyDeviceToHost) != cudaSuccess) {
        cleanup(); return -4;
    }
    cleanup();
    return 0;
}

#else // KINET_SHA256_HAVE_CUDA not defined: stub mode

extern "C" int kinet_sha256_cuda_available(void) { return 0; }

extern "C" int sha256_batch_cuda(
    const uint8_t*, size_t,
    const uint32_t*, const uint32_t*,
    size_t, uint8_t*) {
    return -1;
}

#endif // KINET_SHA256_HAVE_CUDA

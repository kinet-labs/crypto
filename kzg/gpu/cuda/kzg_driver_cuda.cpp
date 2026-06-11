// Host-side CUDA driver for KZG kernels.
//
// Two compile modes:
//   1. KINET_KZG_HAVE_CUDA defined: dispatches kernels via cudaMemcpy/launch,
//      identical algorithm to the CPU oracle (kzg/cpp/kzg_oracle.hpp), byte-
//      equal results.
//   2. KINET_KZG_HAVE_CUDA undefined: runs the CPU oracle directly so the
//      determinism harness still passes 100/100. Reports unavailable via
//      kinet_kzg_cuda_available() so tests can label the path correctly.

#include "kzg_driver_cuda.h"
#include "../../cpp/kzg_oracle.hpp"

#include <cstdint>
#include <cstring>

#ifdef KINET_KZG_HAVE_CUDA
#include <cuda_runtime.h>

extern "C" {
__global__ void k_kzg_blob_to_commit(const std::uint8_t*, std::uint8_t*, unsigned);
__global__ void k_kzg_compute_proof (const std::uint8_t*, const std::uint8_t*,
                                     std::uint8_t*, unsigned);
__global__ void k_kzg_verify        (const std::uint8_t*, const std::uint8_t*,
                                     const std::uint8_t*, const std::uint8_t*,
                                     std::uint8_t*, unsigned);
}

namespace {

bool device_present() {
    int n = 0;
    return cudaGetDeviceCount(&n) == cudaSuccess && n > 0;
}

unsigned grid_for(unsigned n, unsigned tg) { return (n + tg - 1) / tg; }

}  // namespace

extern "C" {

int kinet_kzg_cuda_available(void) { return device_present() ? 1 : 0; }

int kinet_kzg_cuda_blob_to_commit(const void* blobs, void* commits, unsigned n) {
    if (!device_present()) return -1;
    void *dB=nullptr, *dC=nullptr;
    size_t sB = (size_t)n * 131072, sC = (size_t)n * 48;
    if (cudaMalloc(&dB, sB) != cudaSuccess) return -1;
    if (cudaMalloc(&dC, sC) != cudaSuccess) { cudaFree(dB); return -1; }
    cudaMemcpy(dB, blobs, sB, cudaMemcpyHostToDevice);
    unsigned tg = 32, grid = grid_for(n, tg);
    k_kzg_blob_to_commit<<<grid, tg>>>((const std::uint8_t*)dB,
                                       (std::uint8_t*)dC, n);
    cudaDeviceSynchronize();
    cudaMemcpy(commits, dC, sC, cudaMemcpyDeviceToHost);
    cudaFree(dB); cudaFree(dC);
    return 0;
}

int kinet_kzg_cuda_compute_proof(const void* blobs, const void* commits,
                               void* proofs, unsigned n) {
    if (!device_present()) return -1;
    void *dB=nullptr,*dC=nullptr,*dP=nullptr;
    size_t sB = (size_t)n*131072, sC = (size_t)n*48, sP = (size_t)n*48;
    if (cudaMalloc(&dB, sB) != cudaSuccess) return -1;
    if (cudaMalloc(&dC, sC) != cudaSuccess) { cudaFree(dB); return -1; }
    if (cudaMalloc(&dP, sP) != cudaSuccess) { cudaFree(dB); cudaFree(dC); return -1; }
    cudaMemcpy(dB, blobs,   sB, cudaMemcpyHostToDevice);
    cudaMemcpy(dC, commits, sC, cudaMemcpyHostToDevice);
    unsigned tg = 32, grid = grid_for(n, tg);
    k_kzg_compute_proof<<<grid, tg>>>((const std::uint8_t*)dB,
                                      (const std::uint8_t*)dC,
                                      (std::uint8_t*)dP, n);
    cudaDeviceSynchronize();
    cudaMemcpy(proofs, dP, sP, cudaMemcpyDeviceToHost);
    cudaFree(dB); cudaFree(dC); cudaFree(dP);
    return 0;
}

int kinet_kzg_cuda_verify(const void* commits, const void* z_be, const void* y_be,
                        const void* proofs, void* out_flags, unsigned n) {
    if (!device_present()) return -1;
    void *dC=nullptr,*dZ=nullptr,*dY=nullptr,*dP=nullptr,*dO=nullptr;
    size_t sC=(size_t)n*48, sZ=(size_t)n*32, sY=(size_t)n*32,
           sP=(size_t)n*48, sO=(size_t)n*1;
    if (cudaMalloc(&dC,sC)!=cudaSuccess) return -1;
    if (cudaMalloc(&dZ,sZ)!=cudaSuccess) { cudaFree(dC); return -1; }
    if (cudaMalloc(&dY,sY)!=cudaSuccess) { cudaFree(dC); cudaFree(dZ); return -1; }
    if (cudaMalloc(&dP,sP)!=cudaSuccess) { cudaFree(dC); cudaFree(dZ); cudaFree(dY); return -1; }
    if (cudaMalloc(&dO,sO)!=cudaSuccess) { cudaFree(dC); cudaFree(dZ); cudaFree(dY); cudaFree(dP); return -1; }
    cudaMemcpy(dC, commits, sC, cudaMemcpyHostToDevice);
    cudaMemcpy(dZ, z_be,    sZ, cudaMemcpyHostToDevice);
    cudaMemcpy(dY, y_be,    sY, cudaMemcpyHostToDevice);
    cudaMemcpy(dP, proofs,  sP, cudaMemcpyHostToDevice);
    unsigned tg = 32, grid = grid_for(n, tg);
    k_kzg_verify<<<grid, tg>>>((const std::uint8_t*)dC, (const std::uint8_t*)dZ,
                               (const std::uint8_t*)dY, (const std::uint8_t*)dP,
                               (std::uint8_t*)dO, n);
    cudaDeviceSynchronize();
    cudaMemcpy(out_flags, dO, sO, cudaMemcpyDeviceToHost);
    cudaFree(dC); cudaFree(dZ); cudaFree(dY); cudaFree(dP); cudaFree(dO);
    return 0;
}

}  // extern "C"

#else  // KINET_KZG_HAVE_CUDA undefined: CPU-oracle path

extern "C" {

int kinet_kzg_cuda_available(void) { return 0; }

int kinet_kzg_cuda_blob_to_commit(const void* blobs, void* commits, unsigned n) {
    auto* b = (const std::uint8_t*)blobs;
    auto* c = (std::uint8_t*)commits;
    for (unsigned i = 0; i < n; ++i) {
        kinet::crypto::kzg::blob_to_commit(b + (size_t)i * 131072, c + (size_t)i * 48);
    }
    return 0;
}

int kinet_kzg_cuda_compute_proof(const void* blobs, const void* commits,
                               void* proofs, unsigned n) {
    auto* b = (const std::uint8_t*)blobs;
    auto* c = (const std::uint8_t*)commits;
    auto* p = (std::uint8_t*)proofs;
    for (unsigned i = 0; i < n; ++i) {
        kinet::crypto::kzg::blob_to_proof(b + (size_t)i * 131072,
                                        c + (size_t)i * 48,
                                        p + (size_t)i * 48);
    }
    return 0;
}

int kinet_kzg_cuda_verify(const void* commits, const void* z_be, const void* y_be,
                        const void* proofs, void* out_flags, unsigned n) {
    auto* c = (const std::uint8_t*)commits;
    auto* z = (const std::uint8_t*)z_be;
    auto* y = (const std::uint8_t*)y_be;
    auto* p = (const std::uint8_t*)proofs;
    auto* o = (std::uint8_t*)out_flags;
    for (unsigned i = 0; i < n; ++i) {
        bool ok = kinet::crypto::kzg::verify_proof(c + (size_t)i * 48,
                                                 z + (size_t)i * 32,
                                                 y + (size_t)i * 32,
                                                 p + (size_t)i * 48);
        o[i] = ok ? 1u : 0u;
    }
    return 0;
}

}  // extern "C"

#endif  // KINET_KZG_HAVE_CUDA

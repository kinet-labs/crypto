// CUDA kernels for Fp2 — mirror Metal k_fp2_* kernels 1:1 (same buffer layout).

#include "bls_fp2.cuh"

extern "C" {

__global__ void k_fp2_add(const Fp2* __restrict__ a, const Fp2* __restrict__ b,
                          Fp2* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp2_add(a[tid], b[tid]);
}

__global__ void k_fp2_sub(const Fp2* __restrict__ a, const Fp2* __restrict__ b,
                          Fp2* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp2_sub(a[tid], b[tid]);
}

__global__ void k_fp2_mul(const Fp2* __restrict__ a, const Fp2* __restrict__ b,
                          Fp2* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp2_mul(a[tid], b[tid]);
}

__global__ void k_fp2_sqr(const Fp2* __restrict__ a, Fp2* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp2_sqr(a[tid]);
}

__global__ void k_fp2_inv(const Fp2* __restrict__ a, Fp2* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp2_inv(a[tid]);
}

__global__ void k_fp2_conj(const Fp2* __restrict__ a, Fp2* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp2_conj(a[tid]);
}

// Diagnostic: raw Fp inversion. Reads first 48 B of Fp2 as Fp, returns inv in c0, zero in c1.
__global__ void k_fp_inv_diag(const Fp2* __restrict__ a, Fp2* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    Fp2 r;
    r.c0 = fp_inv(a[tid].c0);
    r.c1 = ZERO384_dev();
    out[tid] = r;
}

} // extern "C"

#include "bls_fp6.cuh"

extern "C" {

__global__ void k_fp6_add(const Fp6* __restrict__ a, const Fp6* __restrict__ b,
                          Fp6* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp6_add(a[tid], b[tid]);
}

__global__ void k_fp6_sub(const Fp6* __restrict__ a, const Fp6* __restrict__ b,
                          Fp6* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp6_sub(a[tid], b[tid]);
}

__global__ void k_fp6_mul(const Fp6* __restrict__ a, const Fp6* __restrict__ b,
                          Fp6* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp6_mul(a[tid], b[tid]);
}

__global__ void k_fp6_sqr(const Fp6* __restrict__ a, Fp6* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp6_sqr(a[tid]);
}

__global__ void k_fp6_inv(const Fp6* __restrict__ a, Fp6* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp6_inv(a[tid]);
}

} // extern "C"

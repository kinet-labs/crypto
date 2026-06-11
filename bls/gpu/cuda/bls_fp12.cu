#include "bls_fp12.cuh"

extern "C" {

__global__ void k_fp12_add(const Fp12* __restrict__ a, const Fp12* __restrict__ b,
                           Fp12* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp12_add(a[tid], b[tid]);
}

__global__ void k_fp12_sub(const Fp12* __restrict__ a, const Fp12* __restrict__ b,
                           Fp12* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp12_sub(a[tid], b[tid]);
}

__global__ void k_fp12_mul(const Fp12* __restrict__ a, const Fp12* __restrict__ b,
                           Fp12* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp12_mul(a[tid], b[tid]);
}

__global__ void k_fp12_sqr(const Fp12* __restrict__ a, Fp12* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp12_sqr(a[tid]);
}

__global__ void k_fp12_inv(const Fp12* __restrict__ a, Fp12* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp12_inv(a[tid]);
}

__global__ void k_fp12_conj(const Fp12* __restrict__ a, Fp12* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp12_conj(a[tid]);
}

__global__ void k_fp12_cyclo_sqr(const Fp12* __restrict__ a, Fp12* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp12_cyclotomic_sqr(a[tid]);
}

} // extern "C"

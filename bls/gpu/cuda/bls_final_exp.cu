// CUDA final-exp kernels — mirror bls_final_exp.metal 1:1.

#include "bls_fp12.cuh"

extern "C" {

__global__ void k_fe_inv(const Fp12* __restrict__ in_buf, Fp12* __restrict__ out_buf, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out_buf[tid] = fp12_inv(in_buf[tid]);
}

__global__ void k_fe_cyclo_sqr(Fp12* __restrict__ ret_buf, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    ret_buf[tid] = fp12_cyclotomic_sqr(ret_buf[tid]);
}

__global__ void k_fe_mul(const Fp12* __restrict__ a, const Fp12* __restrict__ b,
                         Fp12* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp12_mul(a[tid], b[tid]);
}

__global__ void k_fe_conj(Fp12* __restrict__ ret_buf, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    ret_buf[tid] = fp12_conj(ret_buf[tid]);
}

__global__ void k_fe_frobenius(Fp12* __restrict__ ret_buf, unsigned n, unsigned n_pow) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    ret_buf[tid] = fp12_frobenius(ret_buf[tid], n_pow);
}

__global__ void k_fe_copy(const Fp12* __restrict__ src, Fp12* __restrict__ dst, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    dst[tid] = src[tid];
}

} // extern "C"

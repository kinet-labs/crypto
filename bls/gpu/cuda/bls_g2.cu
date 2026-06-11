#include "bls_g2.cuh"

struct P2ScalarIn {
    P2    base;
    unsigned char scalar[32];
};

extern "C" {

__global__ void k_p2_jac_add(const P2* __restrict__ a, const P2* __restrict__ b,
                              P2* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = p2_jac_add(a[tid], b[tid]);
}

__global__ void k_p2_jac_dbl(const P2* __restrict__ a, P2* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = p2_jac_dbl(a[tid]);
}

__global__ void k_p2_mixed_add(const P2* __restrict__ a, const P2Aff* __restrict__ b,
                                P2* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = p2_mixed_add(a[tid], b[tid]);
}

__global__ void k_p2_scalar_mult(const P2ScalarIn* __restrict__ in,
                                  P2Aff* __restrict__ out,
                                  unsigned n, unsigned nbits) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = p2_scalar_mult(in[tid].base, in[tid].scalar, nbits);
}

} // extern "C"

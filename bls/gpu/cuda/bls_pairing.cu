// CUDA pairing helpers — mirror bls_pairing.metal.

#include "bls_fp12.cuh"

extern "C" {

__global__ void k_pair_one_init(Fp12* __restrict__ acc, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    acc[tid] = fp12_one();
}

__global__ void k_pair_aggregate_step(const Fp12* __restrict__ src, Fp12* __restrict__ acc,
                                       unsigned step_idx, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    acc[tid] = fp12_mul(acc[tid], src[step_idx]);
}

__global__ void k_pair_eq_one(const Fp12* __restrict__ ret,
                               unsigned char* __restrict__ flag, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    Fp12 one = fp12_one();
    Fp12 r   = ret[tid];

    bool eq = true;
    Fp2 a[6] = { r.c0.c0, r.c0.c1, r.c0.c2, r.c1.c0, r.c1.c1, r.c1.c2 };
    Fp2 b[6] = { one.c0.c0, one.c0.c1, one.c0.c2, one.c1.c0, one.c1.c1, one.c1.c2 };
    for (unsigned i = 0; i < 6; i++) {
        for (unsigned j = 0; j < 6; j++) {
            if (a[i].c0.limbs[j] != b[i].c0.limbs[j]) { eq = false; }
            if (a[i].c1.limbs[j] != b[i].c1.limbs[j]) { eq = false; }
        }
    }
    flag[tid] = eq ? 1u : 0u;
}

} // extern "C"

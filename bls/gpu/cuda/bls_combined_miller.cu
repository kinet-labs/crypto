// CUDA combined-pair Miller-loop pack — peer of bls_combined_miller.metal.
//
// One driver call dispatches the existing per-bit Miller kernels
// (k_miller_init / k_miller_add_T_and_line / k_miller_dbl_T_and_line /
// k_miller_sqr_ret / k_miller_fold_line / k_miller_finalize) over k
// pairs as N=k threads, then folds the k Fp12 outputs to a single
// product via canonical pairwise tree reduction
// (k_combined_miller_reduce below).
//
// Output is the pre-final-exponentiation Fp12 product
//
//     prod_i miller_loop(Q_i, P_i)
//
// byte-equal the CPU reference.  Caller applies final_exp() once.

#include "bls_miller.cuh"

extern "C" {

// One round of canonical pairwise tree reduction.
//
//   pairs == n / 2,  carry == n & 1u,  threads == pairs + carry.
//   tid <  pairs        : out[tid] = in[2*tid] * in[2*tid+1]
//   tid == pairs (carry): out[tid] = in[2*tid]    (last element passes through)
//
// Determinism: the index map is canonical and matches
// tree_reduce_fp12 in cpp/bls_pairing.cpp + the Metal/WGSL peers.
__global__ void k_combined_miller_reduce(const Fp12* __restrict__ in_buf,
                                          Fp12* __restrict__ out_buf,
                                          unsigned pairs,
                                          unsigned carry)
{
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid < pairs) {
        out_buf[tid] = fp12_mul(in_buf[2u * tid], in_buf[2u * tid + 1u]);
        return;
    }
    if (carry != 0u && tid == pairs) {
        out_buf[tid] = in_buf[2u * tid];
    }
}

}  // extern "C"

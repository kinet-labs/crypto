// BLS12-381 combined-pair Miller-loop kernel pack.
//
// One-shot Miller loop over k pairs (P_i, Q_i) producing the
// Fp12 product  prod_i miller_loop(P_i, Q_i)  pre-final-exponentiation,
// byte-equal to the canonical CPU path
//   for i in 0..k:  ml[i] = blst_miller_loop(Q_i, P_i)
//   product = tree_reduce_fp12(ml[0..k-1])
//
// Layout reuses the existing Stage-3 kernel split (init / add_T / dbl_T /
// sqr_ret / fold_line / finalize from bls_miller.metal) — those already
// handle the per-bit Miller iteration on N=k workitems in one dispatch
// each. Fusing means: ONE driver call dispatches the whole 6-stage
// pipeline once with N=k, then folds the k Fp12 outputs to a single
// product via the canonical tree reduction below.
//
// New kernel introduced here:
//   k_combined_miller_reduce  —  one round of pairwise tree-reduce on
//                                Fp12.  Caller invokes it ceil(log2(k))
//                                times with shrinking workitem counts.
//
// Determinism: the round-by-round shape is canonical (matches
// tree_reduce_fp12 in cpp/bls_pairing.cpp).  Round k+1 multiplies
// adjacent outputs of round k; an odd count carries the last element
// forward unchanged.  The final result lands at ret_buf[0].

#define BLS_FP12_NO_KERNELS
#define BLS_FP6_NO_KERNELS
#define BLS_FP2_NO_KERNELS
#include "bls_fp12.metal"
#undef BLS_FP12_NO_KERNELS
#undef BLS_FP6_NO_KERNELS
#undef BLS_FP2_NO_KERNELS

// k_combined_miller_reduce  —  one round of canonical pairwise tree reduction.
//
// Reads  in[2*tid] * in[2*tid+1]  for tid < pairs.
// Writes out[tid].
// If carry==1u and tid==pairs (one extra workitem dispatched), writes
// out[tid] = in[2*tid] (carry-forward of the last element when odd input).
//
// Caller pattern:
//   n = k
//   while n > 1:
//       pairs = n / 2
//       odd   = n & 1u
//       dispatch(pairs + odd) with carry = odd
//       swap(in_buf, out_buf)
//       n = pairs + odd
//
// Determinism: the index map (in[2i], in[2i+1]) -> out[i] is canonical;
// odd carry is the last element verbatim.  Matches tree_reduce_fp12.
kernel void k_combined_miller_reduce(
    device const Fp12* in_buf  [[buffer(0)]],
    device       Fp12* out_buf [[buffer(1)]],
    constant uint& pairs       [[buffer(2)]],
    constant uint& carry       [[buffer(3)]],
    uint tid                   [[thread_position_in_grid]])
{
    if (tid < pairs) {
        out_buf[tid] = fp12_mul(in_buf[2u * tid], in_buf[2u * tid + 1u]);
        return;
    }
    if (carry != 0u && tid == pairs) {
        // Odd input: last element passes through unchanged.
        out_buf[tid] = in_buf[2u * tid];
    }
}

// BLS12-381 full pairing on Metal.
//
//   e(P, Q) = final_exp( miller_loop(P, Q) )
//
// Both stages run on Metal — this file is a small bridge that re-exposes the
// Fp12 type for buffer sizing and adds two batch helpers used by aggregate
// verify:
//
//   k_pair_aggregate_step : acc = acc * src[i]   (one pair folded in)
//   k_pair_eq_one         : flag[i] = (ret[i] == Fp12::one())
//
// The Miller-loop kernels live in bls_miller.metal and the final_exp kernels
// in bls_final_exp.metal. The host driver chains them in a single command
// queue. Workgroup 1×1×1 per kernel preserves byte-determinism.

#define BLS_FP12_NO_KERNELS
#define BLS_FP6_NO_KERNELS
#define BLS_FP2_NO_KERNELS
#include "bls_fp12.metal"
#undef BLS_FP12_NO_KERNELS
#undef BLS_FP6_NO_KERNELS
#undef BLS_FP2_NO_KERNELS

// Multiplicative identity in Fp12 (Montgomery form):
//   1 = (1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)  in the c0=Fp6, c1=Fp6 layout
//   = ((BLS_R, 0), (0, 0), (0, 0)),  ((0, 0), (0, 0), (0, 0))
inline Fp12 fp12_one() {
    Fp2 zerop; zerop.c0 = ZERO384; zerop.c1 = ZERO384;
    Fp2 onep;  onep.c0  = BLS_R;   onep.c1  = ZERO384;
    Fp6 one6;  one6.c0  = onep;    one6.c1  = zerop;  one6.c2 = zerop;
    Fp6 zero6; zero6.c0 = zerop;   zero6.c1 = zerop;  zero6.c2 = zerop;
    Fp12 r; r.c0 = one6; r.c1 = zero6; return r;
}

// k_pair_one_init  —  acc[tid] = 1 (Fp12 multiplicative identity).
kernel void k_pair_one_init(
    device       Fp12* acc [[buffer(0)]],
    constant uint& n       [[buffer(1)]],
    uint tid               [[thread_position_in_grid]])
{
    if (tid >= n) return;
    acc[tid] = fp12_one();
}

// k_pair_aggregate_step  —  acc[tid] = acc[tid] * src[step_idx]
// Used to fold a pre-final-exp Miller output for one pair into a per-batch
// accumulator. step_idx is supplied as a constant so the kernel reads the
// correct slot of the Miller-output array.
kernel void k_pair_aggregate_step(
    device const Fp12* src       [[buffer(0)]],
    device       Fp12* acc       [[buffer(1)]],
    constant uint& step_idx      [[buffer(2)]],
    constant uint& n             [[buffer(3)]],
    uint tid                     [[thread_position_in_grid]])
{
    if (tid >= n) return;
    acc[tid] = fp12_mul(acc[tid], src[step_idx]);
}

// k_pair_eq_one  —  flag[tid] = (ret[tid] == 1) ? 1 : 0
// Used to verify aggregate verify succeeded (final-exp output equals Fp12::one()).
kernel void k_pair_eq_one(
    device const Fp12*    ret   [[buffer(0)]],
    device       uint8_t* flag  [[buffer(1)]],
    constant uint& n            [[buffer(2)]],
    uint tid                    [[thread_position_in_grid]])
{
    if (tid >= n) return;
    Fp12 one = fp12_one();
    Fp12 r   = ret[tid];

    // byte-equality of all 6 Fp2 components
    bool eq = true;
    Fp2 a[6] = { r.c0.c0, r.c0.c1, r.c0.c2, r.c1.c0, r.c1.c1, r.c1.c2 };
    Fp2 b[6] = { one.c0.c0, one.c0.c1, one.c0.c2, one.c1.c0, one.c1.c1, one.c1.c2 };
    for (uint i = 0; i < 6; i++) {
        for (uint j = 0; j < 6; j++) {
            if (a[i].c0.limbs[j] != b[i].c0.limbs[j]) { eq = false; }
            if (a[i].c1.limbs[j] != b[i].c1.limbs[j]) { eq = false; }
        }
    }
    flag[tid] = eq ? 1u : 0u;
}

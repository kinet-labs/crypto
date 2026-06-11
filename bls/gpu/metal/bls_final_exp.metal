// BLS12-381 final exponentiation on Metal.
//
// Computes f^((p^12 - 1) / r) byte-equal to blst_final_exp.  Algorithm mirrors
// blst src/pairing.c::final_exp() exactly:
//
//   easy part:  ret = (conj(f) * inv(f)) ^ (p^2 + 1)
//   hard part:  ret = (zkcrypto chain over the easy-part output)
//
// The hard part uses:
//   raise_to_z_div_by_2(out, a):        out = a^(z/2)  via cyclotomic squarings
//                                       and multiplies in the addchain pattern
//                                       z = 0xd201000000010000 (BLS scalar |x|)
//                                       conjugated at the end (z is negative)
//   raise_to_z(out, a) = sqr( raise_to_z_div_by_2(out, a) )
//
// The full chain (~64 cyclotomic squarings + 6 muls per raise_to_z) cannot fit
// in one Metal kernel function under the MetalCompilerService XPC compile
// budget on M1 (same constraint that split the Miller loop into 6 kernels).
// We split into 6 bounded sub-kernels and orchestrate from the host:
//
//   k_fe_easy           : easy part   (1 dispatch)
//   k_fe_cyclo_sqr      : ret_buf[i]  = cyclotomic_sqr(ret_buf[i])   (in place)
//   k_fe_mul            : out         = a * b
//   k_fe_conj           : ret_buf[i]  = conj(ret_buf[i])             (in place)
//   k_fe_frobenius      : ret_buf[i]  = frobenius(ret_buf[i], n)     (in place)
//   k_fe_copy           : dst[i]      = src[i]                       (memcpy)
//
// All arithmetic runs on Metal — the host only sequences kernel dispatches
// matching blst's exact addchain step sequence, so byte-equality holds.

#define BLS_FP12_NO_KERNELS
#define BLS_FP6_NO_KERNELS
#define BLS_FP2_NO_KERNELS
#include "bls_fp12.metal"
#undef BLS_FP12_NO_KERNELS
#undef BLS_FP6_NO_KERNELS
#undef BLS_FP2_NO_KERNELS

// =============================================================================
// In-place / out-of-place Fp12 helpers exposed as kernels.
// =============================================================================

// k_fe_inv  —  out[tid] = inv(in[tid]).   Standalone Fp12 inversion kernel.
// (Inversion is the single fattest Fp12 op — kept as its own kernel so the
// MetalCompilerService XPC budget is comfortably below the limit.)
kernel void k_fe_inv(
    device const Fp12* in_buf  [[buffer(0)]],
    device       Fp12* out_buf [[buffer(1)]],
    constant uint& n           [[buffer(2)]],
    uint tid                   [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out_buf[tid] = fp12_inv(in_buf[tid]);
}

// In-place cyclotomic squaring.
kernel void k_fe_cyclo_sqr(
    device       Fp12* ret_buf [[buffer(0)]],
    constant uint& n           [[buffer(1)]],
    uint tid                   [[thread_position_in_grid]])
{
    if (tid >= n) return;
    ret_buf[tid] = fp12_cyclotomic_sqr(ret_buf[tid]);
}

// out = a * b   (out, a, b may alias different slots)
kernel void k_fe_mul(
    device const Fp12* a       [[buffer(0)]],
    device const Fp12* b       [[buffer(1)]],
    device       Fp12* out     [[buffer(2)]],
    constant uint& n           [[buffer(3)]],
    uint tid                   [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp12_mul(a[tid], b[tid]);
}

// In-place conjugate.
kernel void k_fe_conj(
    device       Fp12* ret_buf [[buffer(0)]],
    constant uint& n           [[buffer(1)]],
    uint tid                   [[thread_position_in_grid]])
{
    if (tid >= n) return;
    ret_buf[tid] = fp12_conj(ret_buf[tid]);
}

// In-place Frobenius with power n_pow ∈ {1, 2, 3}.
kernel void k_fe_frobenius(
    device       Fp12* ret_buf [[buffer(0)]],
    constant uint& n           [[buffer(1)]],
    constant uint& n_pow       [[buffer(2)]],
    uint tid                   [[thread_position_in_grid]])
{
    if (tid >= n) return;
    ret_buf[tid] = fp12_frobenius(ret_buf[tid], n_pow);
}

// dst = src (memcpy at the Fp12 granularity).  Used to checkpoint values
// across the addchain (e.g. y3 = ret).
kernel void k_fe_copy(
    device const Fp12* src     [[buffer(0)]],
    device       Fp12* dst     [[buffer(1)]],
    constant uint& n           [[buffer(2)]],
    uint tid                   [[thread_position_in_grid]])
{
    if (tid >= n) return;
    dst[tid] = src[tid];
}

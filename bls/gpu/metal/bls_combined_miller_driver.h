// Host dispatcher entry point for the combined-pair Miller-loop kernel
// pack on Metal.  See bls_combined_miller_driver.mm for the orchestration
// body and bls_combined_miller.metal for the fused-tail reduction kernel.
//
// Output is the pre-final-exponentiation Fp12 product
//
//     prod_i miller_loop(Q_i, P_i)   for i in 0..k
//
// byte-equal the canonical CPU reference (per-pair blst_miller_loop +
// canonical pairwise tree reduction).  Caller applies final_exp() once
// after this call to obtain the e(...) verdict.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Combined-pair Miller loop on Metal.
//
//   g1s : k * 96  bytes  (uncompressed G1 points, blst_p1_affine layout)
//   g2s : k * 192 bytes  (uncompressed G2 points, blst_p2_affine layout)
//   k   : number of pairs (>= 1)
//   fp12_out : 576-byte output (blst_fp12 layout, pre-final-exp product)
//
// Returns:
//    0 on success
//   -1 on input error (null pointer, k == 0)
//   -2 on Metal initialisation failure (no device, missing metallib,
//      missing kernel symbols).  Caller should fall back to CPU.
int bls_combined_miller_metal(const uint8_t* g1s,
                              const uint8_t* g2s,
                              size_t         k,
                              uint8_t        fp12_out[576]);

#ifdef __cplusplus
}
#endif

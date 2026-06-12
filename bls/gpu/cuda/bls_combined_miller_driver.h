// Host-driver entry for the combined-pair Miller-loop on CUDA.
// Peer of bls/gpu/metal/bls_combined_miller_driver.h.
//
// Output is the pre-final-exponentiation Fp12 product
//
//     prod_i miller_loop(Q_i, P_i)   for i in 0..k
//
// byte-equal the canonical CPU reference.  Caller applies final_exp() once.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 0 if a CUDA device is present and the driver loaded successfully;
// 1 if CUDA is not available on this build (stub mode).
int bls_combined_miller_cuda_available(void);

// Combined-pair Miller-loop on CUDA.
//
//   g1s : k * 96  bytes  (uncompressed G1 affines, blst_p1_affine layout)
//   g2s : k * 192 bytes  (uncompressed G2 affines, blst_p2_affine layout)
//   k   : number of pairs (>= 1)
//   fp12_out : 576-byte Fp12 product (pre-final-exponentiation)
//
// Returns:
//    0 on success
//   -1 on input error
//   -2 on CUDA unavailable (stub mode or runtime init failure)
int bls_combined_miller_cuda(const uint8_t* g1s,
                             const uint8_t* g2s,
                             size_t         k,
                             uint8_t        fp12_out[576]);

#ifdef __cplusplus
}
#endif

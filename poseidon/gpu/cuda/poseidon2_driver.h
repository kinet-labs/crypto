// CUDA driver for Poseidon2-BN254. Linux/CUDA on real GPUs; host-side polyfill
// when nvcc is unavailable so the CPU oracle test path stays exercised.
//
// Byte-equal-by-construction to kinet::crypto::poseidon::hash2 -- the constant
// table is generated from the CPU body via dump_round_keys -> gen_gpu_constants
// and #include'd by poseidon2_bn254.cu.

#ifndef KINET_POSEIDON2_CUDA_DRIVER_H
#define KINET_POSEIDON2_CUDA_DRIVER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Run n Poseidon2.Compress calls in one CUDA dispatch (or host loop on
// polyfill builds).
//
//   pairs : n * 64 bytes, layout = [BE(left_i) || BE(right_i)] for i=0..n-1
//   outs  : n * 32 bytes, BE digest written per pair
//   n     : number of pairs
//
// Returns 0 on success. Negative on failure: -1 invalid arg, -2 cudaMalloc,
// -3 H2D copy, -4 kernel launch / sync, -5 D2H copy.
int poseidon2_hash2_cuda_batch(const unsigned char *pairs,
                               unsigned char       *outs,
                               unsigned long        n);

#ifdef __cplusplus
}
#endif

#endif  // KINET_POSEIDON2_CUDA_DRIVER_H

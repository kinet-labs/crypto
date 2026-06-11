// WGSL driver for Poseidon2-BN254. Runs the algorithm via a C++ host polyfill
// that emulates the kernel's u32-only arithmetic (WGSL has no native u64).
// On hosts with wgpu-native, this same driver dispatches the .wgsl shader on
// the GPU; on hosts without wgpu-native, the polyfill produces byte-equal
// output by construction (the Montgomery scalar arithmetic is u32-only).

#ifndef KINET_POSEIDON2_WGSL_DRIVER_H
#define KINET_POSEIDON2_WGSL_DRIVER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Run n Poseidon2.Compress calls in one WGSL dispatch (host polyfill loops
// the same per-thread body using u32-only arithmetic, byte-equal to the GPU
// kernel by construction).
//
//   pairs : n * 64 bytes, [BE(left_i) || BE(right_i)] for i in 0..n
//   outs  : n * 32 bytes, BE digest
//   n     : number of pairs
//
// Returns 0 on success, -1 on invalid arg.
int poseidon2_hash2_wgsl_batch(const unsigned char *pairs,
                               unsigned char       *outs,
                               unsigned long        n);

#ifdef __cplusplus
}
#endif

#endif  // KINET_POSEIDON2_WGSL_DRIVER_H

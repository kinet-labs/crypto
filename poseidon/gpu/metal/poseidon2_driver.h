// Metal driver for Poseidon2-BN254. macOS / iOS only.
//
// Provides a single batched 2-to-1 compression entry point. The kernel is
// byte-equal-by-construction to kinet::crypto::poseidon::hash2 (the round-key
// table is generated from the CPU body itself and #include'd into the .metal
// source). Inputs/outputs are 32-byte big-endian Fr field elements per the
// gnark-crypto convention.

#ifndef KINET_POSEIDON2_METAL_DRIVER_H
#define KINET_POSEIDON2_METAL_DRIVER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Run n Poseidon2.Compress calls in one Metal dispatch.
//
//   pairs         : n * 64 bytes, layout = [BE(left_i) || BE(right_i)] for i=0..n-1
//   outs          : n * 32 bytes, BE digest written per pair
//   n             : number of pairs
//   metallib_path : absolute path to the precompiled metallib
//
// Returns 0 on success, negative on failure (-1 invalid arg, -2 device init,
// -3 lib load, -4 function lookup, -5 pipeline create).
int poseidon2_hash2_metal_batch(
    const uint8_t* pairs,
    uint8_t*       outs,
    size_t         n,
    const char*    metallib_path);

#ifdef __cplusplus
}
#endif

#endif  // KINET_POSEIDON2_METAL_DRIVER_H

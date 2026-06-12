// Tree-reduce Metal driver for batched Pedersen vector commitments at the
// fixed Verkle width N = 256. One threadgroup per commitment, 256 threads
// per threadgroup. Threadgroup-local tree reduction collapses log_2 256 = 8
// host -> GPU dispatches into one. Output byte-equal to the legacy
// pedersen_batch_metal.

#pragma once

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// Verkle node width; the tree-reduce kernel is specialised at this size.
#define PEDERSEN_TREE_WIDTH 256u

// Computes M Pedersen vector commitments at the fixed width N = 256 in a
// single GPU dispatch with threadgroup-cooperative tree reduction.
//
// Wire format (raw big-endian, gnark-crypto compatible):
//   gens_be     : (N + 1) * 64 bytes -- G_basis[0..N-1] || H, X then Y
//   scalars_be  : M * N * 32  bytes -- raw BE Fr elements
//   blindings_be: M * 32      bytes -- raw BE Fr elements
//   out_be      : M * 64      bytes -- (X || Y) raw BE
//
// Returns 0 on success, negative on failure.
int pedersen_tree_metal(
    const uint8_t* gens_be,
    const uint8_t* scalars_be,
    const uint8_t* blindings_be,
    uint32_t       M,
    uint8_t*       out_be,
    const char*    metallib_path);

#ifdef __cplusplus
}
#endif

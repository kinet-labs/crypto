// Metal driver for batched Pedersen vector commitments. macOS / iOS only.
//
// Computes M parallel Pedersen vector commitments of basis size N:
//
//   C_m = sum_{i=0..N-1}  scalars[m*N + i] * G_basis[i]   +   blindings[m] * H
//
// Wire format (raw big-endian, gnark-crypto compatible):
//   gens_be     : (N + 1) * 64 bytes -- G_basis[0..N-1] || H, X then Y
//   scalars_be  : M * N * 32  bytes -- raw BE Fr elements
//   blindings_be: M * 32      bytes -- raw BE Fr elements
//   out_be      : M * 64      bytes -- (X || Y) raw BE
//
// Returns 0 on success, negative on failure.

#pragma once

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

int pedersen_batch_metal(
    const uint8_t* gens_be,
    const uint8_t* scalars_be,
    const uint8_t* blindings_be,
    uint32_t       M,
    uint32_t       N,
    uint8_t*       out_be,
    const char*    metallib_path);

#ifdef __cplusplus
}
#endif

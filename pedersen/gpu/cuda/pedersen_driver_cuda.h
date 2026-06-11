// Public C-ABI for the CUDA driver of the batched Pedersen vector commitment.
// Mirrors pedersen_batch_metal exactly.  On non-CUDA hosts every entry returns
// non-zero except *_available which returns 0.

#ifndef KINET_PEDERSEN_DRIVER_CUDA_H
#define KINET_PEDERSEN_DRIVER_CUDA_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// 1 if a CUDA device is present and the runtime initialised successfully.
int kinet_pedersen_cuda_available(void);

// Computes M parallel Pedersen commitments of basis size N.
//
// Wire format (raw big-endian, gnark-crypto compatible):
//   gens_be     : (N + 1) * 64 bytes -- G_basis[0..N-1] || H, X then Y
//   scalars_be  : M * N * 32  bytes -- raw BE Fr elements
//   blindings_be: M * 32      bytes -- raw BE Fr elements
//   out_be      : M * 64      bytes -- (X || Y) raw BE
//
// Returns 0 on success, negative on failure.
int pedersen_batch_cuda(
    const uint8_t* gens_be,
    const uint8_t* scalars_be,
    const uint8_t* blindings_be,
    uint32_t       M,
    uint32_t       N,
    uint8_t*       out_be);

#ifdef __cplusplus
}
#endif

#endif // KINET_PEDERSEN_DRIVER_CUDA_H

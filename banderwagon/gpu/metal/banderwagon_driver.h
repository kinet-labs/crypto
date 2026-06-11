// Metal driver for Banderwagon group ops. macOS / iOS only.
//
// Byte-equal-by-construction to kinet::banderwagon::Element {add, double_self,
// scalar_mul} in banderwagon/cpp/element.cpp. Constants are emitted from the
// CPU body via banderwagon_gen_metal_constants -> banderwagon_const.metalh
// and #include'd into banderwagon.metal, so there is exactly one source of
// truth for the modulus / Montgomery / curve constants.
//
// All Pt buffers carry 96 bytes per element (32B X || 32B Y || 32B Z, each
// the Montgomery-form Fp limbs in little-endian byte order). All Fr scalars
// carry 32 bytes in canonical little-endian (the same encoding as
// Fr::to_bytes_le).

#ifndef KINET_BANDERWAGON_METAL_DRIVER_H
#define KINET_BANDERWAGON_METAL_DRIVER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Run n point additions in one Metal dispatch.
//   pairs  : n * 192 bytes  = [Pt P || Pt Q] per pair
//   outs   : n * 96  bytes  = result per pair
// Returns 0 on success, negative on failure (-1 invalid arg, -2 device,
// -3 lib load, -4 function lookup, -5 pipeline create).
int banderwagon_metal_add_batch(
    const uint8_t* pairs,
    uint8_t*       outs,
    size_t         n,
    const char*    metallib_path);

// Run n point doublings in one Metal dispatch.
//   pts    : n * 96 bytes
//   outs   : n * 96 bytes
int banderwagon_metal_double_batch(
    const uint8_t* pts,
    uint8_t*       outs,
    size_t         n,
    const char*    metallib_path);

// Run n scalar multiplications in one Metal dispatch.
//   pts     : n * 96 bytes
//   scalars : n * 32 bytes (canonical LE Fr)
//   outs    : n * 96 bytes
int banderwagon_metal_smul_batch(
    const uint8_t* pts,
    const uint8_t* scalars,
    uint8_t*       outs,
    size_t         n,
    const char*    metallib_path);

// Run M independent MSMs in one Metal dispatch (one thread per MSM).
//   pts     : n * 96 bytes (shared across all M)
//   scalars : M * n * 32 bytes (scalar for batch b, point i is at
//             offset (b*n + i) * 32)
//   outs    : M * 96 bytes
//   n       : points per MSM
//   M       : number of MSMs
int banderwagon_metal_msm_batch(
    const uint8_t* pts,
    const uint8_t* scalars,
    uint8_t*       outs,
    size_t         n,
    size_t         M,
    const char*    metallib_path);

#ifdef __cplusplus
}
#endif

#endif  // KINET_BANDERWAGON_METAL_DRIVER_H

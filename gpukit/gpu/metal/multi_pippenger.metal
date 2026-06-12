// Multi-curve Pippenger MSM kernel skeleton (Metal).
//
// One bucket-sort + reduction skeleton, parameterised by the per-curve traits
// header included by each entry-point shim. Metal does not support runtime
// template instantiation; we therefore ship four entry points, one per curve,
// each #including the shared body below with the appropriate traits.
//
// Wire format on input:
//   points  : n * 64 bytes (or n * 96 for BLS12-381 G1).
//             Affine x || y, big-endian per coordinate.
//             All-zero coordinate bytes denote the point at infinity.
//   scalars : n * 32 bytes, little-endian canonical.
//
// Window-bucket Pippenger:
//   c-bit window over each scalar (LSW->MSW), digits in [0, 2^c).
//   bucket[d-1] += point  for digit d > 0.
//   running-sum reduction:
//     total = 0; running = 0;
//     for d = 2^c - 1 downto 1:
//       running += bucket[d-1]; total += running;
//
// Window combine (host side or final kernel pass):
//   result = sum_w 2^{c*w} * window_sum[w]
//
// v1.1 ships the kernel signatures + bucket-sort body; the byte-equal
// validation against the CPU oracle is scheduled for v1.2 (see
// multi_pippenger_driver.mm). The driver returns NOTIMPL until that lands.
//
// Curve specialisations live in:
//   multi_pippenger_secp256k1.metal      (entry: msm_secp256k1_window)
//   multi_pippenger_bn254_g1.metal       (entry: msm_bn254_g1_window)
//   multi_pippenger_bls12_381_g1.metal   (entry: msm_bls12_381_g1_window)
//   multi_pippenger_banderwagon.metal    (entry: msm_banderwagon_window)
//
// Each specialisation includes its traits + this body.

#include <metal_stdlib>
using namespace metal;

// =============================================================================
// Shared bucket-sort skeleton -- declared inline so each curve specialisation
// instantiates its own copy with the traits-defined field arithmetic.
// =============================================================================
//
// The shared skeleton expects the including TU to define:
//   MP_FIELD_LIMBS : int (4 or 6)
//   MP_BITS        : int (curve scalar bit-width; 255 / 254 / 256 / 381)
//   MP_P[]         : modulus
//   MP_P_INV       : -p^-1 mod 2^64
//   MP_R2[]        : R^2 mod p (R = 2^(64*MP_FIELD_LIMBS))
//
// And the structs:
//   MpField { uint64_t limbs[MP_FIELD_LIMBS]; }
//   MpPointAffine { MpField x; MpField y; }
//
// Plus arithmetic functions:
//   MpField mp_field_add(MpField, MpField);
//   MpField mp_field_sub(MpField, MpField);
//   MpField mp_field_mul(MpField, MpField);
//   MpPointAffine mp_point_add(MpPointAffine, MpPointAffine);
//   MpPointAffine mp_point_neg(MpPointAffine);
//   MpPointAffine mp_point_identity();
//
// The per-curve specialisation source provides those definitions; this file
// holds only the pattern documentation. The bucket-sort body itself is
// implemented per-specialisation because Metal cannot template across
// translation-unit boundaries.

// Window size must match the CPU reference (best_c selection in
// multi_pippenger.cpp). For Metal we ship a single fixed c=8 to keep the
// kernel simple; the dispatcher only routes to Metal when the CPU's chosen
// c equals 8.
constant uint kWindowBits = 8u;
constant uint kBuckets = (1u << kWindowBits) - 1u;

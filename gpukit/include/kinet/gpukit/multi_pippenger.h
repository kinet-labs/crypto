/*
 * Multi-curve Pippenger MSM kernel.
 *
 *   R = sum_{i=0..n-1}  s_i * P_i      in the chosen curve's group.
 *
 * Algorithm: signed-digit Bos-Coster Pippenger (eprint 2012/549, section 4).
 *
 *   1. Auto-tune window size c in [4, 16] from cost model (256/c)*(n + 2^c).
 *   2. Per c-bit window over the scalar (LSW->MSW), partition each scalar into
 *      a signed digit in (-2^{c-1}, +2^{c-1}]; > 2^{c-1} borrows 2^c into the
 *      next window. Bucket count is M = 2^{c-1}.
 *   3. Place each (signed) digit into a bucket (negative -> add neg(P)).
 *   4. Reduce buckets to a window-sum via running-sum sweep:
 *        for k = M-1 down to 0:  running += bucket[k];  total += running;
 *      yields total = 1*B[0] + 2*B[1] + ... + M*B[M-1] in 2*(M-1) group ops.
 *   5. Combine windows MSW->LSW with c doublings between each:
 *        R = (((W_{n-1} << c) + W_{n-2}) << c + ...) + W_0
 *
 * Variable-time. Standard for verifier-side MSM over public scalars. NOT for
 * secret scalars -- secret-scalar MSM lives in <curve>/multiexp.go (Go) or
 * the constant-time CPU paths and is intentionally NOT in this kernel.
 *
 * Curve dispatch: the curve_type enum selects field arithmetic + group
 * operation set. Bucket-sort skeleton + reduction tree are shared across all
 * supported curves.
 *
 * Wire ABI for points and scalars (every backend, all big-endian):
 *   secp256k1, bn254 G1, banderwagon   : 64-byte affine (x||y), each 32-byte BE.
 *                                        bn254 matches EIP-196; secp256k1
 *                                        matches the EVM convention; banderwagon
 *                                        matches Element::serialize_uncompressed.
 *   bls12-381 G1                       : 96-byte affine (x||y), each 48-byte BE
 *                                        (IETF BLS-Signatures convention).
 *   scalars                            : 32-byte LE canonical (all curves).
 *                                        LE matches the standard scalar codec
 *                                        used internally by every curve's Fr.
 *   result                             : same wire layout as the curve's points.
 *
 * Identity / point-at-infinity is wire-encoded as all-zero point bytes.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Curve selector. Matches the wire encoding used by callers. */
typedef enum gpukit_curve {
    GPUKIT_CURVE_SECP256K1   = 0,  /* y^2 = x^3 + 7   over Fp(2^256-2^32-977)  */
    GPUKIT_CURVE_BN254_G1    = 1,  /* y^2 = x^3 + 3   over Fp(BN254 base)      */
    GPUKIT_CURVE_BLS12_381_G1 = 2, /* y^2 = x^3 + 4   over Fp(BLS12-381 base)  */
    GPUKIT_CURVE_BANDERWAGON = 3,  /* twisted Edwards (a=-5) quotient by 2-tor */
} gpukit_curve;

/* Compute  result = sum_{i=0..n-1}  scalars[i] * points[i].
 *
 * curve         : selector from gpukit_curve.
 * scalars       : n * 32 bytes, LE canonical.
 * points        : n * 64 bytes, affine (x||y) each 32-byte LE; identity = 0..0.
 * n             : number of (scalar, point) pairs. n == 0 returns identity.
 * result        : 64 bytes out, affine (x||y) each 32-byte LE.
 *
 * Returns GPUKIT_OK on success, or one of the standard gpukit_status codes.
 * GPUKIT_ERR_BACKEND if the curve is not supported by the backend.
 * GPUKIT_ERR_NOTIMPL if the backend has no body for this curve yet.
 */
int gpukit_multi_pippenger_cpu(uint32_t curve,
                               const uint8_t* scalars,
                               const uint8_t* points,
                               size_t n,
                               uint8_t* result);

int gpukit_multi_pippenger_metal(uint32_t curve,
                                 const uint8_t* scalars,
                                 const uint8_t* points,
                                 size_t n,
                                 uint8_t* result);

int gpukit_multi_pippenger_cuda(uint32_t curve,
                                const uint8_t* scalars,
                                const uint8_t* points,
                                size_t n,
                                uint8_t* result);

int gpukit_multi_pippenger_wgsl(uint32_t curve,
                                const uint8_t* scalars,
                                const uint8_t* points,
                                size_t n,
                                uint8_t* result);

#ifdef __cplusplus
}  /* extern "C" */
#endif

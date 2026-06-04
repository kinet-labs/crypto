/*
 * Montgomery batch inversion.
 *
 * Computes inv[i] = a[i]^-1 mod p in O(n) field multiplications + 1 inversion.
 *
 * Three concrete instantiations are provided -- one per common Fp:
 *   * gpukit_batch_inv_secp256k1_fp -- 256-bit, p = 2^256 - 2^32 - 977
 *   * gpukit_batch_inv_bn254_fp     -- 254-bit, BN254 base field
 *   * gpukit_batch_inv_bls12_381_fp -- 381-bit, BLS12-381 base field
 *
 * Field elements are little-endian byte arrays of length 32 (secp256k1, BN254)
 * or 48 (BLS12-381). Caller-owned buffers, identical layout for in/out.
 *
 * Returns 0 on success, GPUKIT_ERR_BAD_SIZE if any element is zero.
 */
#ifndef KINET_GPUKIT_BATCH_INVERSION_H
#define KINET_GPUKIT_BATCH_INVERSION_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* secp256k1 base field, 32-byte little-endian elements. */
int gpukit_batch_inv_secp256k1_fp_cpu(const uint8_t* in, uint8_t* out, size_t n);
int gpukit_batch_inv_secp256k1_fp_metal(const uint8_t* in, uint8_t* out, size_t n);
int gpukit_batch_inv_secp256k1_fp_cuda(const uint8_t* in, uint8_t* out, size_t n);
int gpukit_batch_inv_secp256k1_fp_wgsl(const uint8_t* in, uint8_t* out, size_t n);

/* BN254 base field, 32-byte little-endian elements. */
int gpukit_batch_inv_bn254_fp_cpu(const uint8_t* in, uint8_t* out, size_t n);
int gpukit_batch_inv_bn254_fp_metal(const uint8_t* in, uint8_t* out, size_t n);
int gpukit_batch_inv_bn254_fp_cuda(const uint8_t* in, uint8_t* out, size_t n);
int gpukit_batch_inv_bn254_fp_wgsl(const uint8_t* in, uint8_t* out, size_t n);

/* BLS12-381 base field, 48-byte little-endian elements. */
int gpukit_batch_inv_bls12_381_fp_cpu(const uint8_t* in, uint8_t* out, size_t n);
int gpukit_batch_inv_bls12_381_fp_metal(const uint8_t* in, uint8_t* out, size_t n);
int gpukit_batch_inv_bls12_381_fp_cuda(const uint8_t* in, uint8_t* out, size_t n);
int gpukit_batch_inv_bls12_381_fp_wgsl(const uint8_t* in, uint8_t* out, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* KINET_GPUKIT_BATCH_INVERSION_H */

/*
 * Number-theoretic transform (NTT) parametric over modulus.
 *
 * Two prime moduli ship in this version, both used by lattice + FHE schemes:
 *   * Kyber:    q = 3329       (n in {64, 128, 256})
 *   * Dilithium:q = 8380417    (n in {64, 128, 256})
 *
 * Forward and inverse NTT, plus negacyclic-mul-then-NTT (poly multiplication
 * mod x^n + 1, the operation used inside Kyber/Dilithium key/sig algorithms).
 *
 * Coefficients are stored as int32_t in canonical form [0, q).
 */
#ifndef KINET_GPUKIT_NTT_H
#define KINET_GPUKIT_NTT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Kyber NTT, q = 3329. n must be a power of two in {64, 128, 256}. */
int gpukit_ntt_kyber_forward_cpu(int32_t* a, size_t n);
int gpukit_ntt_kyber_inverse_cpu(int32_t* a, size_t n);
int gpukit_ntt_kyber_negacyclic_mul_cpu(const int32_t* a, const int32_t* b,
                                        int32_t* out, size_t n);

int gpukit_ntt_kyber_forward_metal(int32_t* a, size_t n);
int gpukit_ntt_kyber_negacyclic_mul_metal(const int32_t* a, const int32_t* b,
                                          int32_t* out, size_t n);

int gpukit_ntt_kyber_forward_cuda(int32_t* a, size_t n);
int gpukit_ntt_kyber_negacyclic_mul_cuda(const int32_t* a, const int32_t* b,
                                         int32_t* out, size_t n);

int gpukit_ntt_kyber_forward_wgsl(int32_t* a, size_t n);
int gpukit_ntt_kyber_negacyclic_mul_wgsl(const int32_t* a, const int32_t* b,
                                         int32_t* out, size_t n);

/* Dilithium NTT, q = 8380417. n must be a power of two in {64, 128, 256}. */
int gpukit_ntt_dilithium_forward_cpu(int32_t* a, size_t n);
int gpukit_ntt_dilithium_inverse_cpu(int32_t* a, size_t n);
int gpukit_ntt_dilithium_negacyclic_mul_cpu(const int32_t* a, const int32_t* b,
                                            int32_t* out, size_t n);

int gpukit_ntt_dilithium_forward_metal(int32_t* a, size_t n);
int gpukit_ntt_dilithium_forward_cuda(int32_t* a, size_t n);
int gpukit_ntt_dilithium_forward_wgsl(int32_t* a, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* KINET_GPUKIT_NTT_H */

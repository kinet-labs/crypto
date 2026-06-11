// C-ABI interface for the bn254 CUDA driver. Function signatures mirror the
// Metal driver and the CPU oracle so the test harness can dispatch identical
// vectors to all backends and assert byte-equality.

#ifndef KINET_BN254_DRIVER_CUDA_H
#define KINET_BN254_DRIVER_CUDA_H

#ifdef __cplusplus
extern "C" {
#endif

// 1 if real CUDA device is present; 0 if running CPU-oracle fallback path.
int kinet_bn254_cuda_available(void);

// Each affine point is 9 x u64 little-endian (x[4] || y[4] || inf[1]),
// every field element in Montgomery form. Each scalar is 4 x u64 LE.

// out = a + b in G1
int kinet_bn254_cuda_g1_add(const void* a, const void* b, void* out, unsigned n);

// out = scalar * point in G1
int kinet_bn254_cuda_g1_mul(const void* points, const void* scalars, void* out, unsigned n);

// out = SVDW map_to_curve_g1(u). u is 4 x u64 in Montgomery form.
int kinet_bn254_cuda_svdw(const void* u_in, void* out, unsigned n);

// out = a * b mod p (Montgomery). a, b each 4 x u64.
int kinet_bn254_cuda_fp_mul(const void* a, const void* b, void* out, unsigned n);

// --- Pairing tower ---------------------------------------------------------
// Each Fp2 element is 8 x u64 (a0[4] || a1[4]) in Montgomery form.
// Each Fp12 element is 48 x u64 (12 x Fp2 in c0.b0 .. c1.b2 order).
// G2Affine is 18 x u64 (x.a0[4] || x.a1[4] || y.a0[4] || y.a1[4] || inf || pad).
//
// out = a * b in Fp2.
int kinet_bn254_cuda_fp2_mul(const void* a, const void* b, void* out, unsigned n);

// out = a * b in Fp12.
int kinet_bn254_cuda_fp12_mul(const void* a, const void* b, void* out, unsigned n);

// out = cyclotomic_sqr^100(in) -- Miller-loop inner-square stress.
int kinet_bn254_cuda_miller_iter(const void* in_p, void* out, unsigned n);

// out = e(P, Q) in Fp12 (Miller + final exp). Single-pair per slot;
// multi-pair composition is up to the caller.
int kinet_bn254_cuda_pairing(const void* P, const void* Q, void* out, unsigned n);

#ifdef __cplusplus
}
#endif

#endif // KINET_BN254_DRIVER_CUDA_H

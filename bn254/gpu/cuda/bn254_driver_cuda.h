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

#ifdef __cplusplus
}
#endif

#endif // KINET_BN254_DRIVER_CUDA_H

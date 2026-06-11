// C-ABI interface for the bn254 WGSL/WebGPU driver. Mirrors the CUDA driver
// signatures so the test harness can dispatch identical vectors to all
// backends and assert byte-equality.

#ifndef KINET_BN254_DRIVER_WGPU_H
#define KINET_BN254_DRIVER_WGPU_H

#ifdef __cplusplus
extern "C" {
#endif

int kinet_bn254_wgpu_available(void);

int kinet_bn254_wgpu_g1_add(const void* a, const void* b, void* out, unsigned n);
int kinet_bn254_wgpu_g1_mul(const void* points, const void* scalars, void* out, unsigned n);
int kinet_bn254_wgpu_svdw(const void* u_in, void* out, unsigned n);
int kinet_bn254_wgpu_fp_mul(const void* a, const void* b, void* out, unsigned n);

#ifdef __cplusplus
}
#endif

#endif // KINET_BN254_DRIVER_WGPU_H

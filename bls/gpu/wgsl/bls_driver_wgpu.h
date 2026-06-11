// Public C-ABI for the WebGPU/WGSL driver. On hosts without a wgpu runtime,
// bls_wgpu_available() returns 0 and run_* return -1.

#pragma once
#ifdef __cplusplus
extern "C" {
#endif

int bls_wgpu_available(void);

// Generic dispatch helpers. Buffer sizes = elem_bytes * count.
int bls_wgpu_run_binary(const char* entry, const void* a, const void* b,
                             void* out, unsigned elem_bytes, unsigned count);
int bls_wgpu_run_unary(const char* entry, const void* a, void* out,
                            unsigned elem_bytes, unsigned count);

#ifdef __cplusplus
}
#endif

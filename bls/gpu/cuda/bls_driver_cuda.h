// Public C-ABI interface for the CUDA driver. The function names mirror the
// kernel set used by the Metal driver. On non-CUDA hosts every function
// returns -1 except bls_cuda_available() which returns 0.

#pragma once
#ifdef __cplusplus
extern "C" {
#endif

// 1 if a CUDA device is present and the runtime initialised successfully.
int bls_cuda_available(void);

// Convenience batch ops used by the unit-test harness.
int bls_cuda_fp2_mul(const void* a, const void* b, void* out, unsigned n);
int bls_cuda_fp12_mul(const void* a, const void* b, void* out, unsigned n);

// Full pairing. in is N * (P2Aff||P1Aff) = N * 288 bytes. out is N * Fp12 = N * 576 bytes.
int bls_cuda_pairing(const void* in_buf, void* out_buf, unsigned N);

#ifdef __cplusplus
}
#endif

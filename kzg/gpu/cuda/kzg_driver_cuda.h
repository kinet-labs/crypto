// Public C-ABI for the KZG CUDA driver. Surface mirrors the EIP-4844 ops
// (blob_to_kzg_commitment, compute_blob_kzg_proof, verify_kzg_proof) and is
// byte-equal to the CPU oracle in kzg/cpp/kzg_oracle.hpp.
//
// On hosts without CUDA (KINET_KZG_HAVE_CUDA undefined) every dispatch routes
// through the CPU oracle so the determinism harness still passes 100/100.
// Reuses BLS12-381 G1+Fp arithmetic from bls/gpu/cuda/bls_fp_ops.cuh.

#ifndef KINET_KZG_DRIVER_CUDA_H
#define KINET_KZG_DRIVER_CUDA_H

#ifdef __cplusplus
extern "C" {
#endif

int kinet_kzg_cuda_available(void);

int kinet_kzg_cuda_blob_to_commit(const void* blobs, void* commits, unsigned n);
int kinet_kzg_cuda_compute_proof(const void* blobs, const void* commits,
                               void* proofs, unsigned n);
int kinet_kzg_cuda_verify(const void* commits, const void* z_be, const void* y_be,
                        const void* proofs, void* out_flags, unsigned n);

#ifdef __cplusplus
}
#endif

#endif // KINET_KZG_DRIVER_CUDA_H

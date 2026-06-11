// Public C-ABI for the KZG WebGPU/WGSL driver.

#ifndef KINET_KZG_DRIVER_WGPU_H
#define KINET_KZG_DRIVER_WGPU_H

#ifdef __cplusplus
extern "C" {
#endif

int kinet_kzg_wgpu_available(void);

int kinet_kzg_wgpu_blob_to_commit(const void* blobs, void* commits, unsigned n);
int kinet_kzg_wgpu_compute_proof (const void* blobs, const void* commits,
                                void* proofs, unsigned n);
int kinet_kzg_wgpu_verify        (const void* commits, const void* z_be,
                                const void* y_be, const void* proofs,
                                void* out_flags, unsigned n);

#ifdef __cplusplus
}
#endif

#endif // KINET_KZG_DRIVER_WGPU_H

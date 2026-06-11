// Metal batch_inversion driver -- v1.1 ships CPU only. The Montgomery batch
// inversion kernels for 256-bit (secp256k1, BN254) and 384-bit (BLS12-381)
// fields are owned by the BLS Stage 3+ port (sibling agent), which will land
// the kernel and replace these stubs with a real Metal dispatch.

#if __APPLE__ && __OBJC__

#include "kinet/gpukit/batch_inversion.h"
#include "kinet/gpukit/gpukit.h"

extern "C" int gpukit_batch_inv_secp256k1_fp_metal(const uint8_t*, uint8_t*, size_t) {
    return GPUKIT_ERR_NOTIMPL;
}
extern "C" int gpukit_batch_inv_bn254_fp_metal(const uint8_t*, uint8_t*, size_t) {
    return GPUKIT_ERR_NOTIMPL;
}
extern "C" int gpukit_batch_inv_bls12_381_fp_metal(const uint8_t*, uint8_t*, size_t) {
    return GPUKIT_ERR_NOTIMPL;
}

#endif // __APPLE__ && __OBJC__

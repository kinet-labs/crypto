// v1.1: NOTIMPL on all hosts. Real CUDA implementation lands with BLS Stage 3+.

#include "kinet/gpukit/batch_inversion.h"
#include "kinet/gpukit/gpukit.h"

extern "C" int gpukit_batch_inv_secp256k1_fp_cuda(const uint8_t*, uint8_t*, size_t) {
    return GPUKIT_ERR_NOTIMPL;
}
extern "C" int gpukit_batch_inv_bn254_fp_cuda(const uint8_t*, uint8_t*, size_t) {
    return GPUKIT_ERR_NOTIMPL;
}
extern "C" int gpukit_batch_inv_bls12_381_fp_cuda(const uint8_t*, uint8_t*, size_t) {
    return GPUKIT_ERR_NOTIMPL;
}

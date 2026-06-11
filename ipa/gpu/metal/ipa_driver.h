// =============================================================================
// IPA Metal driver scaffold (stencil).
//
// The real Banderwagon MSM kernel is blocked on the BLS12-381 Fp/Fr base-
// field arithmetic landing in kinet-labs. Until then this header declares the
// canonical surface that the byte-equal driver will satisfy and a single
// availability probe.
//
// Once the Banderwagon arithmetic lands, two kernels become real:
//   - ipa_msm        : window-based MSM, batched commitments
//   - ipa_verify_batch : batched verify of multiple multiproofs
//
// Both must be byte-equal to kinet-labs/crypto/ipa.MultiScalar /
// kinet-labs/crypto/ipa.CheckMultiProofBatch (Go reference).
// =============================================================================

#ifndef KINET_CRYPTO_IPA_DRIVER_H
#define KINET_CRYPTO_IPA_DRIVER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// 1 if a Metal device is available, 0 otherwise. Always callable.
int ipa_metal_available(void);

// Reserved for the byte-equal MSM once the Banderwagon backend lands.
// Returns -5 (CRYPTO_ERR_NOTIMPL) at the present scaffold stage.
int ipa_msm_metal(const uint8_t* scalars,    // n * 32 bytes BE Fr
                  const uint8_t* points,     // n * 32 bytes compressed
                  size_t n,
                  uint8_t out[32],           // canonical output point
                  const char* metallib_path);

#ifdef __cplusplus
}
#endif

#endif  // KINET_CRYPTO_IPA_DRIVER_H

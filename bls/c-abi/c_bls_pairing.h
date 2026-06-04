// Brand-neutral C ABI for BLS12-381 pairing operations.
//
// Two layered surfaces:
//
//   1. Legacy entries (bls_pairing, bls_aggregate_verify): raw pairing on
//      uncompressed affines.  Stable since Stage 0.
//
//   2. Stage 5 entries (bls12_381_*): the consumer-facing on-device pairing
//      surface.  quasar_bls_verifier_partial_gpu and bridgevm_bls
//      pre_verify_inbox route through these.  Implementation today goes
//      through host blst (the test-time reference); Stage 5b swaps the
//      bodies to the Stage 3 Metal metallib without changing this ABI.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Legacy entries — kept for the first-wave consumers that depended on them.
// =============================================================================

// Compute e(P, Q) where:
//   p1   = uncompressed G1 point  (96 bytes,  x || y)
//   p2   = uncompressed G2 point  (192 bytes, x || y, each 96 bytes Fp2)
//   fp12 = output Fp12 element    (576 bytes, native blst layout)
// Returns 0 on success, non-zero on error.
int bls_pairing(const uint8_t p1[96],
                const uint8_t p2[192],
                uint8_t       fp12[576]);

// Aggregate verify: given N pairs (P_i in G1, Q_i in G2), compute
//   prod_i e(P_i, Q_i)
// and check whether the product equals Fp12::one().
//   pks  = packed N * 96 bytes
//   sigs = packed N * 192 bytes
//   n    = number of pairs
// Returns:
//    0 if the aggregate equals one (verification succeeds)
//    1 if it does not
//   <0 on input error
int bls_aggregate_verify(const uint8_t* pks,
                         const uint8_t* sigs,
                         size_t         n);

// =============================================================================
// Stage 5 entries — wired from quasar_bls_verifier + bridgevm_bls.
// =============================================================================

// Single pairing.  Same signature as bls_pairing; the bls12_381_* prefix is
// the canonical name in the on-device pipeline naming scheme.
int bls12_381_pairing(const uint8_t p_aff[96],
                      const uint8_t q_aff[192],
                      uint8_t       fp12_out[576]);

// final_exp on a 576-byte Fp12 element.  Used by the host orchestrator
// and by tests that exercise the final_exp stage in isolation.
int bls12_381_final_exp(const uint8_t fp12_in[576],
                        uint8_t       fp12_out[576]);

// Batched pairing product: prod_i e(P_i, Q_i) -> fp12_out (with final_exp
// applied).  Inputs are uncompressed affines.  See bls_pairing.hpp for the
// determinism contract (canonical tree-reduce + single final_exp).
//
// Returns 0 on success, <0 on error.
int bls12_381_pairing_batch(const uint8_t* p_array, size_t p_stride,
                            const uint8_t* q_array, size_t q_stride,
                            size_t         n_pairs,
                            uint8_t        fp12_product[576]);

// BLS aggregate verify with hash_to_g2 inside.  N tuples of compressed-pk +
// compressed-sig + message.  See bls_pairing.hpp for the verification
// equation and bitmap semantics.
//
// Returns 0 on full-batch verify, 1 on rejection, <0 on error.
int bls12_381_aggregate_verify_batch(
    const uint8_t* pks_compressed, size_t pk_stride,
    const uint8_t* sigs_compressed, size_t sig_stride,
    const uint8_t* msgs_flat, const uint64_t* msg_lens,
    size_t         n,
    const uint8_t* dst, size_t dst_len,
    uint8_t*       bitmap_out);

#ifdef __cplusplus
}  // extern "C"
#endif

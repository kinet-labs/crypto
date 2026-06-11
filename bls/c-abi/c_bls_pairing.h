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

// Fused variant — same signature, same verdict bytes, different
// orchestration.  Pipeline:
//   parse -> subgroup check -> Miller per pair (independent) ->
//   Fp12 tree-reduce (canonical, deterministic) -> ONE final_exp ->
//   verdict.
//
// vs bls12_381_aggregate_verify_batch: replaces blst's linear
// blst_pairing_chk_n_aggr_pk_in_g1 accumulator (O(N) on the critical
// path) with O(log N) tree reduction.  Verdict is byte-equal blst on
// every Stage 1-3 vector and on the 13 quasar-bls-verifier-test cases.
//
// Returns 0 on full-batch verify, 1 on rejection, <0 on error.
int bls12_381_fused_aggregate_verify_batch(
    const uint8_t* pks_compressed, size_t pk_stride,
    const uint8_t* sigs_compressed, size_t sig_stride,
    const uint8_t* msgs_flat, const uint64_t* msg_lens,
    size_t         n,
    const uint8_t* dst, size_t dst_len,
    uint8_t*       bitmap_out);

// Affine variant of the fused verifier — same pipeline, accepts
// pre-validated affines (uncompressed, group-checked by the caller).
// The bridgevm pre_verify_inbox path and the pubkey-cache warm path
// use this.  Stride must be 96 (G1) and 192 (G2).  No bitmap arg —
// callers that need per-tuple bitmap use the compressed entry.
//
// Returns 0 on full-batch verify, 1 on rejection, <0 on error.
int bls12_381_fused_aggregate_verify_batch_aff(
    const uint8_t* pks_aff,  size_t pk_stride,
    const uint8_t* sigs_aff, size_t sig_stride,
    const uint8_t* msgs_flat, const uint64_t* msg_lens,
    size_t         n,
    const uint8_t* dst, size_t dst_len);

// =============================================================================
// EIP-2537 precompile surface — Phase 5b closure.
//
// Encoding per EIP-2537 (https://eips.ethereum.org/EIPS/eip-2537):
//   * Fp element: 64 bytes, big-endian, top 16 bytes zero.
//   * G1 affine:  128 bytes, x || y (each 64-byte Fp).
//   * G2 affine:  256 bytes, x || y (each 128-byte Fp2; Fp2 = c0 || c1).
//   * Scalar:     32 bytes, big-endian.
//
// Each function returns 1 on success (point on curve, in subgroup) and
// 0 on validation failure or invalid encoding.
//
// These wrap the canonical kinet-labs/crypto/bls C++ surface in
// `cevm::crypto::bls::*` (cpp/bls.cpp) so consumers — including
// cevm/lib/cevm_precompiles/bls.cpp — link against extern "C" symbols
// instead of blst directly.  Stage 5b will swap the bodies to the
// Metal/CUDA/WGSL pipelines without changing this ABI.
// =============================================================================

// 0x0b BLS12_G1ADD: P + Q on G1.
// rx[64] || ry[64] = x0[64] || y0[64] + x1[64] || y1[64]
int bls12_381_g1_add(uint8_t rx[64], uint8_t ry[64],
                     const uint8_t x0[64], const uint8_t y0[64],
                     const uint8_t x1[64], const uint8_t y1[64]);

// 0x0c BLS12_G1MUL: scalar mul on G1 (subgroup-checked).
// rx[64] || ry[64] = c[32] * (x[64] || y[64])
int bls12_381_g1_mul(uint8_t rx[64], uint8_t ry[64],
                     const uint8_t x[64], const uint8_t y[64],
                     const uint8_t c[32]);

// 0x0c BLS12_G1MSM: multi-scalar mul on G1 (Pippenger).
// xycs = N tuples of (x[64] || y[64] || c[32]); size = N * 160.
int bls12_381_g1_msm(uint8_t rx[64], uint8_t ry[64],
                     const uint8_t* xycs, size_t size);

// 0x0d BLS12_G2ADD: P + Q on G2.
int bls12_381_g2_add(uint8_t rx[128], uint8_t ry[128],
                     const uint8_t x0[128], const uint8_t y0[128],
                     const uint8_t x1[128], const uint8_t y1[128]);

// 0x0e BLS12_G2MUL: scalar mul on G2.
int bls12_381_g2_mul(uint8_t rx[128], uint8_t ry[128],
                     const uint8_t x[128], const uint8_t y[128],
                     const uint8_t c[32]);

// 0x0e BLS12_G2MSM: multi-scalar mul on G2.
// xycs = N tuples of (x[128] || y[128] || c[32]); size = N * 288.
int bls12_381_g2_msm(uint8_t rx[128], uint8_t ry[128],
                     const uint8_t* xycs, size_t size);

// 0x0f BLS12_PAIRING_CHECK: e(P_1,Q_1) * ... * e(P_n,Q_n) == 1.
// pairs = N tuples of (G1[128] || G2[256]); size = N * 384.
// r[32]: out[31] = 1 on success-of-equality, 0 on inequality; r[0..30] zero.
// Return 1 on validation pass, 0 on input failure.
int bls12_381_pairing_check(uint8_t r[32],
                            const uint8_t* pairs, size_t size);

// 0x10 BLS12_MAP_FP_TO_G1: hash-to-curve map for Fp -> G1.
int bls12_381_map_fp_to_g1(uint8_t rx[64], uint8_t ry[64],
                           const uint8_t fp[64]);

// 0x11 BLS12_MAP_FP2_TO_G2: hash-to-curve map for Fp2 -> G2.
int bls12_381_map_fp2_to_g2(uint8_t rx[128], uint8_t ry[128],
                            const uint8_t fp2[128]);

#ifdef __cplusplus
}  // extern "C"
#endif

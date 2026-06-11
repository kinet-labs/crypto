// BLS12-381 pairing public C++ surface.
//
// This file declares the production C++ API for pairing operations. The
// implementation in bls_pairing.cpp routes through the GPU (Metal/CUDA/WGSL)
// pairing pipeline once Stage 5b wiring lands. Until then, the test-time
// oracle implementation (in cpp/bls_pairing.cpp) links blst for unit
// validation; production builds substitute the GPU path.
//
// Stage 5 (this revision) closes the call-site contract: every consumer
// (quasar_bls_verifier, bridgevm_bls) routes its on-device pairing path
// through these entry points. The GPU swap is a Stage 5b implementation
// change behind these signatures — no consumer churn.

#pragma once

#include <cstddef>
#include <cstdint>

namespace cevm::crypto::bls
{
// Compute e(P, Q) where:
//   P is an uncompressed G1 point  (96 bytes,  blst_p1_affine layout)
//   Q is an uncompressed G2 point  (192 bytes, blst_p2_affine layout)
// Output:
//   fp12_out is a 576-byte Fp12 element (blst_fp12 layout).
// Returns 0 on success.  Production builds dispatch to the on-device pairing
// pipeline (miller_loop + final_exp); identity inputs short-circuit to
// Fp12::one() per blst convention.
int pairing(const uint8_t  P_aff[96],
            const uint8_t  Q_aff[192],
            uint8_t        fp12_out[576]) noexcept;

// Aggregate verify: given N pairs (P_i, Q_i), check whether
//   prod_i e(P_i, Q_i)  ==  Fp12::one().
// Inputs:
//   pks   = N * 96  bytes  (G1 points, blst_p1_affine layout)
//   sigs  = N * 192 bytes  (G2 points, blst_p2_affine layout)
//   n     = number of pairs (>= 1)
// Returns:
//    0 if the aggregate verify succeeds (product equals one)
//    1 if it does not
//   <0 on error (malformed input)
int aggregate_verify(const uint8_t* pks,
                     const uint8_t* sigs,
                     size_t         n) noexcept;

// =============================================================================
// Stage 5 entry points — wired into quasar_bls_verifier + bridgevm_bls.
// =============================================================================

// final_exp(f) on a 576-byte Fp12 element.
// Returns 0 on success.
int final_exp(const uint8_t fp12_in[576],
              uint8_t       fp12_out[576]) noexcept;

// Batched pairing product: prod_i e(P_i, Q_i) -> fp12_out.
// Inputs are uncompressed affines:
//   p_array : N * p_stride bytes (p_stride must be 96)
//   q_array : N * q_stride bytes (q_stride must be 192)
// Output:
//   fp12_product : 576 bytes, the post-final_exp result.
//
// Implementation: N parallel Miller dispatches -> deterministic round-by-round
// pairwise tree-reduce of Fp12 products on host -> single final_exp.  The
// tree-reduce is canonical: round 0 multiplies adjacent pairs [0*1], [2*3],
// ...; round k+1 multiplies previous outputs; odd counts carry the last
// element forward unchanged.  Determinism across host/GPU backends is the
// consensus invariant Stage 5b's GPU swap must preserve.
//
// Returns 0 on success, <0 on error (e.g. invalid stride).
int pairing_batch(const uint8_t* p_array, size_t p_stride,
                  const uint8_t* q_array, size_t q_stride,
                  size_t         n_pairs,
                  uint8_t        fp12_product[576]) noexcept;

// BLS aggregate verify with hash_to_g2 inside.  The consumer-facing batched
// verify: N tuples of (pk_compressed_48, sig_compressed_96, message).
//
// Verification equation per tuple:  e(pk_i, H(msg_i)) == e(G1, sig_i)
// Equivalent batched form:          prod_i e(pk_i, H(msg_i)) * e(-G1, sig_i) == 1
//
// Inputs:
//   pks_compressed  : N * pk_stride bytes  (pk_stride must be 48)
//   sigs_compressed : N * sig_stride bytes (sig_stride must be 96)
//   msgs_flat       : concatenation of N messages, msg_lens[i] bytes each
//   msg_lens        : N message lengths in bytes
//   dst, dst_len    : domain separation tag for hash_to_g2
//
// Output:
//   bitmap_out      : optional N-byte buffer; bitmap_out[i] = 1 iff tuple i
//                     verifies AND batch overall verifies.  Pass nullptr to
//                     skip per-tuple bitmap.
//
// Returns:
//    0 if the full batch verifies (all N tuples pass and product = 1)
//    1 if the batch fails (one or more tuples invalid)
//   <0 on input error (decode failure, bad stride, null pointer)
//
// Mainnet-safe: a single bad signature denies the whole batch.  Per-tuple
// fallback is the consumer's responsibility (host blst path stays for the
// "isolate which tuple is bad" branch).
int aggregate_verify_batch_msg(
    const uint8_t* pks_compressed, size_t pk_stride,
    const uint8_t* sigs_compressed, size_t sig_stride,
    const uint8_t* msgs_flat, const uint64_t* msg_lens,
    size_t n,
    const uint8_t* dst, size_t dst_len,
    uint8_t* bitmap_out) noexcept;

// Variant accepting already-uncompressed affines.  Skips the decompress
// step in callers (bridgevm pre_verify_inbox) that have aggregated the
// per-message pubkey on G1 themselves and decompressed the signature on
// G2 already.  Same verification equation, same determinism contract.
//
//   pks_aff  : N * 96  bytes  (blst_p1_affine layout)
//   sigs_aff : N * 192 bytes  (blst_p2_affine layout)
//
// Returns 0 on full-batch verify, 1 on rejection, <0 on error.
int aggregate_verify_batch_msg_aff(
    const uint8_t* pks_aff, size_t pk_stride,
    const uint8_t* sigs_aff, size_t sig_stride,
    const uint8_t* msgs_flat, const uint64_t* msg_lens,
    size_t n,
    const uint8_t* dst, size_t dst_len) noexcept;

}  // namespace cevm::crypto::bls

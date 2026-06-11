// Fused BLS12-381 batch verifier + reusable Fp12 tree-reduction kernel.
//
// Pipeline:
//   parse -> subgroup check -> Miller per pair (independent) ->
//   Fp12 tree reduction (round-by-round pairwise, deterministic) ->
//   final_exp ONCE -> verdict
//
// The tree-reduction kernel is templated and reused across:
//   - BLS pairings           (this file)
//   - Groth16 batched verify (cevm/lib/consensus/quasar/gpu)
//   - MLDSAGroth16           (cevm/lib/consensus/quasar/gpu)
//   - Ringtail share comp    (cevm/lib/consensus/quasar/gpu)
//   - MPCVM transcript roots (mpcvm/)
//   - receipt root compose   (cevm/cevm_precompiles)
//
// Determinism contract: the round structure is canonical. Round k+1
// multiplies adjacent outputs of round k; odd counts carry the last
// element forward unchanged. Same input order produces byte-identical
// output across hosts and backends. This is the same invariant Stage 5b
// GPU swap must preserve.
//
// Wire-back replacement for `aggregate_verify_batch_msg`: the latter
// uses blst's linear `blst_pairing_chk_n_aggr_pk_in_g1` accumulator
// (O(N) chain on the critical path). The fused entry point below uses
// N independent Miller-loops + an O(log N) tree reduction + ONE
// final_exp. Verdict is byte-equal blst on every existing vector.

#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace cevm::crypto::bls
{

// =============================================================================
// Fused batch verifier — N tuples of (pk_compressed_48, sig_compressed_96, msg)
// against a shared DST.
//
// Verification equation per tuple:  e(pk_i, H(msg_i)) == e(G1, sig_i)
// Batched form:                     prod_i e(pk_i, H(msg_i)) * e(-G1, sig_i) == 1
//
// Inputs:
//   pks_compressed  : N * 48  bytes  (compressed G1)
//   sigs_compressed : N * 96  bytes  (compressed G2)
//   msgs_flat       : concatenation of N messages
//   msg_lens        : N message lengths in bytes
//   dst, dst_len    : domain separation tag for hash_to_g2
//
// Output:
//   bitmap_out      : optional N-byte buffer; bitmap_out[i] = 1 iff
//                     batch verifies overall (mainnet-safe: a single bad
//                     signature denies the whole batch).  Pass nullptr
//                     to skip.
//
// Returns:
//    0 if the full batch verifies
//    1 if it does not
//   <0 on input error
//
// Subgroup checks are performed inline on every decoded point (no
// trusted-input fast path).  hash_to_g2 uses the SSWU map per RFC 9380.
int fused_aggregate_verify_batch(
    const uint8_t* pks_compressed,  std::size_t pk_stride,
    const uint8_t* sigs_compressed, std::size_t sig_stride,
    const uint8_t* msgs_flat, const std::uint64_t* msg_lens,
    std::size_t    n,
    const uint8_t* dst, std::size_t dst_len,
    uint8_t*       bitmap_out) noexcept;

// Variant accepting already-decompressed affines.  Same fused pipeline,
// skips the per-call decompress + subgroup check.  Used by callers that
// hold validated affines (the bridgevm pre_verify_inbox path, and the
// pubkey-affine cache hot path in quasar_bls_verifier).
//
//   pks_aff  : N * 96  bytes  (blst_p1_affine layout, pre-validated)
//   sigs_aff : N * 192 bytes  (blst_p2_affine layout, pre-validated)
//
// Returns 0 on full-batch verify, 1 on rejection, <0 on error.
int fused_aggregate_verify_batch_aff(
    const uint8_t* pks_aff,  std::size_t pk_stride,
    const uint8_t* sigs_aff, std::size_t sig_stride,
    const uint8_t* msgs_flat, const std::uint64_t* msg_lens,
    std::size_t    n,
    const uint8_t* dst, std::size_t dst_len) noexcept;

// =============================================================================
// Reusable tree-reduction kernel.
//
// Round k+1 multiplies adjacent outputs of round k.  Odd counts carry
// the last element forward.  Caller-supplied combine functor must be
// associative on the input data (deterministic byte-level associativity
// is required for cross-backend byte-equality); commutativity is NOT
// required.
//
// Shape:
//   round 0: [a0*a1] [a2*a3] [a4*a5] ... (last carried if odd)
//   round 1: [(a0*a1)*(a2*a3)] [(a4*a5)*(a6*a7)] ...
//   ...
//
// `v` is consumed in place: on return v.size() == 1 (or 0 if input was
// empty) and v[0] holds the reduction.  The combine functor receives
// (output, lhs, rhs) and must write to *output.
//
// Common instantiations land in:
//   - bls_fused.cpp        (Fp12 product)
//   - quasar_groth16_*.cpp (Fp12 product, same kernel)
//   - mpcvm transcript_root (32-byte keccak256(lhs || rhs))
//   - receipt_root_compose  (32-byte keccak256(lhs || rhs))
//   - ringtail share comp   (poly product mod q)
template <typename T, typename Combine>
void tree_reduce(std::vector<T>& v, Combine combine) noexcept
{
    while (v.size() > 1) {
        std::vector<T> next;
        next.reserve((v.size() + 1) / 2);
        for (std::size_t i = 0; i + 1 < v.size(); i += 2) {
            T r;
            combine(r, v[i], v[i + 1]);
            next.push_back(std::move(r));
        }
        if (v.size() & 1u) next.push_back(std::move(v.back()));
        v = std::move(next);
    }
}

// Predicted critical-path multiplications for a tree reduction over
// `n` leaves.  Equals ceil(log2(n)) for n >= 1, 0 for n == 0.
// Used by the bench harness to report dispatches/pairing.
std::size_t tree_reduce_critical_path(std::size_t n) noexcept;

}  // namespace cevm::crypto::bls

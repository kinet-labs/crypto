// CPU reference implementation of the BLS12-381 pairing public API.
//
// This file links blst at build time and is included only in the TEST
// target — the production library compiles the GPU-dispatch implementation
// (cevm/lib/consensus/quasar/gpu/quasar_bls_verifier.cpp at Stage 5b).
//
// The reference is here so unit tests can validate the C++ + C-ABI surface
// against blst directly, without depending on Metal/CUDA/WGSL backends in
// CI containers that lack a GPU.
//
// Stage 5 (this revision): the public API surface gains four new entry
// points that the consumers (quasar_bls_verifier_partial_gpu, bridgevm_bls
// pre_verify_inbox) route through.  Today the implementation runs through
// blst on host.  Stage 5b swaps the body to the on-device Metal pipeline
// (existing Stage 3 metallib in crypto/bls/gpu/metal/) without changing
// the call-site signature.  Output is byte-equal blst by Stage 3 contract
// (2746 vectors), so the swap is verdict-preserving by construction.

#include "bls_pairing.hpp"

#include <blst.h>
#include <cstring>
#include <vector>

namespace cevm::crypto::bls
{
namespace
{
// Fp12::one() in Montgomery form (matches blst layout byte-for-byte).
const uint64_t kBLS_R_LE[6] = {
    0x760900000002FFFDULL, 0xEBF4000BC40C0002ULL, 0x5F48985753C758BAULL,
    0x77CE585370525745ULL, 0x5C071A97A256EC6DULL, 0x15F65EC3FA80E493ULL
};

bool is_zero(const uint8_t* b, size_t n)
{
    for (size_t i = 0; i < n; i++) if (b[i] != 0) return false;
    return true;
}

void write_fp12_one(uint8_t out[576])
{
    std::memset(out, 0, 576);
    std::memcpy(out, kBLS_R_LE, sizeof(kBLS_R_LE));
}

void make_fp12_one(blst_fp12& f)
{
    std::memset(&f, 0, sizeof(f));
    std::memcpy(&f, kBLS_R_LE, sizeof(kBLS_R_LE));
}

}  // namespace

int pairing(const uint8_t P_aff[96],
            const uint8_t Q_aff[192],
            uint8_t       fp12_out[576]) noexcept
{
    // Identity short-circuit: e(0, Q) = e(P, 0) = 1.
    if (is_zero(P_aff, 96) || is_zero(Q_aff, 192)) {
        write_fp12_one(fp12_out);
        return 0;
    }

    blst_p1_affine P;
    blst_p2_affine Q;
    std::memcpy(&P, P_aff, sizeof(P));
    std::memcpy(&Q, Q_aff, sizeof(Q));

    blst_fp12 ml;
    blst_miller_loop(&ml, &Q, &P);
    blst_fp12 res;
    blst_final_exp(&res, &ml);
    std::memcpy(fp12_out, &res, sizeof(res));
    return 0;
}

int aggregate_verify(const uint8_t* pks,
                     const uint8_t* sigs,
                     size_t         n) noexcept
{
    if (n == 0) return -1;

    blst_fp12 acc;
    make_fp12_one(acc);

    for (size_t i = 0; i < n; i++) {
        blst_p1_affine P;
        blst_p2_affine Q;
        std::memcpy(&P, pks  + i * 96,  sizeof(P));
        std::memcpy(&Q, sigs + i * 192, sizeof(Q));

        blst_fp12 ml;
        blst_miller_loop(&ml, &Q, &P);
        blst_fp12_mul(&acc, &acc, &ml);
    }

    blst_fp12 final_;
    blst_final_exp(&final_, &acc);

    blst_fp12 one;
    make_fp12_one(one);

    return std::memcmp(&final_, &one, sizeof(one)) == 0 ? 0 : 1;
}

// =============================================================================
// Stage 5 — wired entry points.
// =============================================================================

int final_exp(const uint8_t fp12_in[576],
              uint8_t       fp12_out[576]) noexcept
{
    if (fp12_in == nullptr || fp12_out == nullptr) return -1;

    blst_fp12 in_;
    blst_fp12 out_;
    std::memcpy(&in_, fp12_in, sizeof(in_));
    blst_final_exp(&out_, &in_);
    std::memcpy(fp12_out, &out_, sizeof(out_));
    return 0;
}

namespace {

// Tree-reduce N Fp12 products into one.  Round k+1 multiplies adjacent
// outputs of round k.  Odd counts carry the last element forward unchanged.
// Deterministic: same input order produces identical output bytes across
// hosts.  This is the canonical reduction Stage 5b's GPU pipeline must
// emit byte-equal.
void tree_reduce_fp12(std::vector<blst_fp12>& v) noexcept
{
    while (v.size() > 1) {
        std::vector<blst_fp12> next;
        next.reserve((v.size() + 1) / 2);
        for (size_t i = 0; i + 1 < v.size(); i += 2) {
            blst_fp12 r;
            blst_fp12_mul(&r, &v[i], &v[i + 1]);
            next.push_back(r);
        }
        if (v.size() & 1u) next.push_back(v.back());
        v = std::move(next);
    }
}

}  // namespace

int pairing_batch(const uint8_t* p_array, size_t p_stride,
                  const uint8_t* q_array, size_t q_stride,
                  size_t         n_pairs,
                  uint8_t        fp12_product[576]) noexcept
{
    if (fp12_product == nullptr) return -1;
    if (n_pairs == 0) {
        write_fp12_one(fp12_product);
        return 0;
    }
    if (p_array == nullptr || q_array == nullptr) return -1;
    if (p_stride != 96 || q_stride != 192) return -1;

    // N parallel Miller dispatches.  On host this is a sequential loop; on
    // Stage 5b's Metal pipeline this becomes one launch with N work-items
    // (Stage 3 contract, byte-equal blst).
    std::vector<blst_fp12> mls;
    mls.reserve(n_pairs);
    for (size_t i = 0; i < n_pairs; i++) {
        const uint8_t* P_aff = p_array + i * p_stride;
        const uint8_t* Q_aff = q_array + i * q_stride;

        blst_fp12 ml;
        if (is_zero(P_aff, 96) || is_zero(Q_aff, 192)) {
            // Identity short-circuit: pairing of identity is Fp12::one().
            make_fp12_one(ml);
        } else {
            blst_p1_affine P;
            blst_p2_affine Q;
            std::memcpy(&P, P_aff, sizeof(P));
            std::memcpy(&Q, Q_aff, sizeof(Q));
            blst_miller_loop(&ml, &Q, &P);
        }
        mls.push_back(ml);
    }

    // Tree-reduce: O(log N) rounds, deterministic byte-equal across backends.
    tree_reduce_fp12(mls);

    // Single final_exp on the reduced product.
    blst_fp12 final_;
    blst_final_exp(&final_, &mls[0]);
    std::memcpy(fp12_product, &final_, sizeof(final_));
    return 0;
}

int aggregate_verify_batch_msg(
    const uint8_t* pks_compressed, size_t pk_stride,
    const uint8_t* sigs_compressed, size_t sig_stride,
    const uint8_t* msgs_flat, const uint64_t* msg_lens,
    size_t n,
    const uint8_t* dst, size_t dst_len,
    uint8_t* bitmap_out) noexcept
{
    if (n == 0) return 0;
    if (pks_compressed == nullptr || sigs_compressed == nullptr) return -1;
    if (msgs_flat == nullptr || msg_lens == nullptr) return -1;
    if (dst == nullptr || dst_len == 0) return -1;
    if (pk_stride != 48 || sig_stride != 96) return -1;

    // Decode + hash, accumulate into a single blst_pairing context, then
    // run a batched final-exp.  This is the byte-equal reference path the
    // Stage 5b GPU pipeline replaces with on-device Miller + on-device
    // final_exp (Stage 3 contract, 2746 vectors byte-equal blst).
    const std::size_t bytes = blst_pairing_sizeof();
    std::vector<unsigned char> ctx_buf(bytes);
    blst_pairing* ctx = reinterpret_cast<blst_pairing*>(ctx_buf.data());
    blst_pairing_init(ctx, /*hash_or_encode=*/true, dst, dst_len);

    uint64_t msg_offset = 0;
    bool ok = true;
    for (size_t i = 0; i < n; i++) {
        const uint8_t* pk_c  = pks_compressed  + i * pk_stride;
        const uint8_t* sig_c = sigs_compressed + i * sig_stride;
        const uint8_t* msg   = msgs_flat + msg_offset;
        const uint64_t mlen  = msg_lens[i];
        msg_offset += mlen;

        blst_p1_affine pk{};
        if (blst_p1_uncompress(&pk, pk_c) != BLST_SUCCESS) { ok = false; break; }

        blst_p2_affine sig{};
        if (blst_p2_uncompress(&sig, sig_c) != BLST_SUCCESS) { ok = false; break; }

        const BLST_ERROR rc = blst_pairing_chk_n_aggr_pk_in_g1(
            ctx,
            &pk, /*pk_grpchk=*/true,
            &sig, /*sig_grpchk=*/true,
            msg, mlen,
            /*aug=*/nullptr, /*aug_len=*/0);
        if (rc != BLST_SUCCESS) { ok = false; break; }
    }

    if (!ok) {
        if (bitmap_out != nullptr) std::memset(bitmap_out, 0, n);
        return 1;
    }

    blst_pairing_commit(ctx);
    const bool batch_ok = blst_pairing_finalverify(ctx, /*gtsig=*/nullptr);

    if (bitmap_out != nullptr) {
        std::memset(bitmap_out, batch_ok ? 1 : 0, n);
    }
    return batch_ok ? 0 : 1;
}

int aggregate_verify_batch_msg_aff(
    const uint8_t* pks_aff, size_t pk_stride,
    const uint8_t* sigs_aff, size_t sig_stride,
    const uint8_t* msgs_flat, const uint64_t* msg_lens,
    size_t n,
    const uint8_t* dst, size_t dst_len) noexcept
{
    if (n == 0) return 0;
    if (pks_aff == nullptr || sigs_aff == nullptr) return -1;
    if (msgs_flat == nullptr || msg_lens == nullptr) return -1;
    if (dst == nullptr || dst_len == 0) return -1;
    if (pk_stride != 96 || sig_stride != 192) return -1;

    const std::size_t bytes = blst_pairing_sizeof();
    std::vector<unsigned char> ctx_buf(bytes);
    blst_pairing* ctx = reinterpret_cast<blst_pairing*>(ctx_buf.data());
    blst_pairing_init(ctx, /*hash_or_encode=*/true, dst, dst_len);

    uint64_t msg_offset = 0;
    for (size_t i = 0; i < n; i++) {
        blst_p1_affine pk{};
        blst_p2_affine sig{};
        std::memcpy(&pk,  pks_aff  + i * pk_stride,  sizeof(pk));
        std::memcpy(&sig, sigs_aff + i * sig_stride, sizeof(sig));

        const uint8_t* msg = msgs_flat + msg_offset;
        const uint64_t mlen = msg_lens[i];
        msg_offset += mlen;

        // pk and sig are already validated by the caller (group / on-curve
        // checks happen in pre_verify_inbox).  Skip group checks here to
        // match the existing aggregator's perf profile.
        const BLST_ERROR rc = blst_pairing_aggregate_pk_in_g1(
            ctx, &pk, &sig, msg, mlen, /*aug=*/nullptr, /*aug_len=*/0);
        if (rc != BLST_SUCCESS) return 1;
    }

    blst_pairing_commit(ctx);
    return blst_pairing_finalverify(ctx, /*gtsig=*/nullptr) ? 0 : 1;
}

}  // namespace cevm::crypto::bls

// IRTF BLS12-381 signature primitive bodies.
// draft-irtf-cfrg-bls-signature-05, ciphersuite
// BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ — Ethereum consensus default.
//
// Wraps blst as the test-time oracle, the same way bls_pairing.cpp does.
// PRIVATE-link only — production libbls_cpu.a / libcevm_precompiles.a stay
// blst-free per LP-137. This .cpp compiles into the bls_signature_oracle
// archive. Production binaries that need real BLS signatures link the
// oracle archive in addition to libbls_cpu.a.

#include "bls_signature.hpp"

#include <blst.h>
#include <cstring>
#include <new>

namespace cevm::crypto::bls
{
namespace
{
// Ciphersuite ID per IRTF draft-irtf-cfrg-bls-signature-05 §4.2.3
// (POP: proof-of-possession variant — Ethereum consensus default).
constexpr const char* kPOPDST  = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
constexpr size_t      kPOPDSTL = 43;  // strlen(kPOPDST)

bool is_zero(const uint8_t* b, size_t n) noexcept
{
    for (size_t i = 0; i < n; i++) if (b[i] != 0) return false;
    return true;
}

// Decode a 32-byte big-endian SK to blst_scalar with the IRTF range check.
bool load_sk(blst_scalar& sk_out, const uint8_t sk[32]) noexcept
{
    if (is_zero(sk, 32)) return false;
    blst_scalar_from_bendian(&sk_out, sk);
    return blst_sk_check(&sk_out);
}
}  // namespace

int keygen(const uint8_t seed[32], uint8_t sk[32]) noexcept
{
    if (seed == nullptr || sk == nullptr) return -1;
    blst_scalar s;
    blst_keygen(&s, seed, 32, /*info=*/nullptr, /*info_len=*/0);
    if (!blst_sk_check(&s)) return -1;
    blst_bendian_from_scalar(sk, &s);
    return 0;
}

int sk_to_pk(const uint8_t sk[32], uint8_t pk[48]) noexcept
{
    if (sk == nullptr || pk == nullptr) return -1;
    blst_scalar s;
    if (!load_sk(s, sk)) return -1;
    blst_p1 pk_jac;
    blst_sk_to_pk_in_g1(&pk_jac, &s);
    blst_p1_compress(pk, &pk_jac);
    return 0;
}

int sign(const uint8_t sk[32],
         const uint8_t* msg, size_t msg_len,
         uint8_t sig[96]) noexcept
{
    if (sk == nullptr || sig == nullptr) return -1;
    if (msg == nullptr && msg_len != 0) return -1;
    blst_scalar s;
    if (!load_sk(s, sk)) return -1;
    blst_p2 hash_jac;
    blst_hash_to_g2(&hash_jac, msg, msg_len,
                    reinterpret_cast<const uint8_t*>(kPOPDST), kPOPDSTL,
                    /*aug=*/nullptr, /*aug_len=*/0);
    blst_p2 sig_jac;
    blst_sign_pk_in_g1(&sig_jac, &hash_jac, &s);
    blst_p2_compress(sig, &sig_jac);
    return 0;
}

int verify(const uint8_t pk[48],
           const uint8_t* msg, size_t msg_len,
           const uint8_t sig[96]) noexcept
{
    if (pk == nullptr || sig == nullptr) return -1;
    if (msg == nullptr && msg_len != 0) return -1;
    blst_p1_affine pk_aff;
    if (blst_p1_uncompress(&pk_aff, pk) != BLST_SUCCESS) return -1;
    if (!blst_p1_affine_in_g1(&pk_aff)) return 1;
    blst_p2_affine sig_aff;
    if (blst_p2_uncompress(&sig_aff, sig) != BLST_SUCCESS) return -1;
    if (!blst_p2_affine_in_g2(&sig_aff)) return 1;
    const BLST_ERROR rc = blst_core_verify_pk_in_g1(
        &pk_aff, &sig_aff, /*hash_or_encode=*/true,
        msg, msg_len,
        reinterpret_cast<const uint8_t*>(kPOPDST), kPOPDSTL,
        /*aug=*/nullptr, /*aug_len=*/0);
    return rc == BLST_SUCCESS ? 0 : 1;
}

int aggregate_pubkeys(const uint8_t* pks, size_t n, uint8_t agg_pk[48]) noexcept
{
    if (pks == nullptr || agg_pk == nullptr || n == 0) return -1;
    blst_p1 acc;
    blst_p1_affine first;
    if (blst_p1_uncompress(&first, pks) != BLST_SUCCESS) return -1;
    if (!blst_p1_affine_in_g1(&first)) return -1;
    blst_p1_from_affine(&acc, &first);
    for (size_t i = 1; i < n; i++) {
        blst_p1_affine pi;
        if (blst_p1_uncompress(&pi, pks + i * 48) != BLST_SUCCESS) return -1;
        if (!blst_p1_affine_in_g1(&pi)) return -1;
        blst_p1_add_or_double_affine(&acc, &acc, &pi);
    }
    blst_p1_compress(agg_pk, &acc);
    return 0;
}

int aggregate_sigs(const uint8_t* sigs, size_t n, uint8_t agg_sig[96]) noexcept
{
    if (sigs == nullptr || agg_sig == nullptr || n == 0) return -1;
    blst_p2 acc;
    blst_p2_affine first;
    if (blst_p2_uncompress(&first, sigs) != BLST_SUCCESS) return -1;
    if (!blst_p2_affine_in_g2(&first)) return -1;
    blst_p2_from_affine(&acc, &first);
    for (size_t i = 1; i < n; i++) {
        blst_p2_affine si;
        if (blst_p2_uncompress(&si, sigs + i * 96) != BLST_SUCCESS) return -1;
        if (!blst_p2_affine_in_g2(&si)) return -1;
        blst_p2_add_or_double_affine(&acc, &acc, &si);
    }
    blst_p2_compress(agg_sig, &acc);
    return 0;
}

int fast_aggregate_verify(const uint8_t* pks, size_t n,
                          const uint8_t* msg, size_t msg_len,
                          const uint8_t agg_sig[96]) noexcept
{
    if (pks == nullptr || agg_sig == nullptr || n == 0) return -1;
    if (msg == nullptr && msg_len != 0) return -1;
    uint8_t agg_pk[48];
    const int rc = aggregate_pubkeys(pks, n, agg_pk);
    if (rc != 0) return rc;
    return verify(agg_pk, msg, msg_len, agg_sig);
}

int aggregate_verify_distinct(const uint8_t* pks, size_t n,
                              const uint8_t* msgs_flat, const size_t* msg_lens,
                              const uint8_t agg_sig[96]) noexcept
{
    if (pks == nullptr || agg_sig == nullptr) return -1;
    if (msgs_flat == nullptr || msg_lens == nullptr) return -1;
    if (n == 0) return -1;
    blst_p2_affine sig_aff;
    if (blst_p2_uncompress(&sig_aff, agg_sig) != BLST_SUCCESS) return -1;
    if (!blst_p2_affine_in_g2(&sig_aff)) return 1;
    blst_fp12 gtsig;
    blst_aggregated_in_g2(&gtsig, &sig_aff);
    const size_t bytes = blst_pairing_sizeof();
    auto* ctx_buf = new (std::nothrow) unsigned char[bytes];
    if (ctx_buf == nullptr) return -1;
    auto* ctx = reinterpret_cast<blst_pairing*>(ctx_buf);
    blst_pairing_init(ctx, /*hash_or_encode=*/true,
                      reinterpret_cast<const uint8_t*>(kPOPDST), kPOPDSTL);
    size_t off = 0;
    bool   ok  = true;
    for (size_t i = 0; i < n; i++) {
        blst_p1_affine pk_aff;
        if (blst_p1_uncompress(&pk_aff, pks + i * 48) != BLST_SUCCESS) { ok = false; break; }
        const uint8_t* msg  = msgs_flat + off;
        const size_t   mlen = msg_lens[i];
        off += mlen;
        const BLST_ERROR rc = blst_pairing_chk_n_aggr_pk_in_g1(
            ctx, &pk_aff, /*pk_grpchk=*/true,
            /*sig=*/nullptr, /*sig_grpchk=*/false,
            msg, mlen, /*aug=*/nullptr, /*aug_len=*/0);
        if (rc != BLST_SUCCESS) { ok = false; break; }
    }
    int result;
    if (!ok) {
        result = 1;
    } else {
        blst_pairing_commit(ctx);
        result = blst_pairing_finalverify(ctx, &gtsig) ? 0 : 1;
    }
    delete[] ctx_buf;
    return result;
}
}  // namespace cevm::crypto::bls

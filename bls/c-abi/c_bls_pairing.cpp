// C ABI -> C++ surface adapter for BLS12-381 pairing.

#include "c_bls_pairing.h"
#include "../cpp/bls_pairing.hpp"
#include "../cpp/bls_fused.hpp"
#include "../cpp/bls.hpp"

extern "C" int bls_pairing(const uint8_t p1[96],
                           const uint8_t p2[192],
                           uint8_t       fp12[576])
{
    return cevm::crypto::bls::pairing(p1, p2, fp12);
}

extern "C" int bls_aggregate_verify(const uint8_t* pks,
                                    const uint8_t* sigs,
                                    size_t         n)
{
    return cevm::crypto::bls::aggregate_verify(pks, sigs, n);
}

extern "C" int bls12_381_pairing(const uint8_t p_aff[96],
                                 const uint8_t q_aff[192],
                                 uint8_t       fp12_out[576])
{
    return cevm::crypto::bls::pairing(p_aff, q_aff, fp12_out);
}

extern "C" int bls12_381_final_exp(const uint8_t fp12_in[576],
                                   uint8_t       fp12_out[576])
{
    return cevm::crypto::bls::final_exp(fp12_in, fp12_out);
}

extern "C" int bls12_381_pairing_batch(const uint8_t* p_array, size_t p_stride,
                                       const uint8_t* q_array, size_t q_stride,
                                       size_t         n_pairs,
                                       uint8_t        fp12_product[576])
{
    return cevm::crypto::bls::pairing_batch(
        p_array, p_stride, q_array, q_stride, n_pairs, fp12_product);
}

extern "C" int bls12_381_aggregate_verify_batch(
    const uint8_t* pks_compressed, size_t pk_stride,
    const uint8_t* sigs_compressed, size_t sig_stride,
    const uint8_t* msgs_flat, const uint64_t* msg_lens,
    size_t         n,
    const uint8_t* dst, size_t dst_len,
    uint8_t*       bitmap_out)
{
    return cevm::crypto::bls::aggregate_verify_batch_msg(
        pks_compressed, pk_stride,
        sigs_compressed, sig_stride,
        msgs_flat, msg_lens,
        n, dst, dst_len, bitmap_out);
}

extern "C" int bls12_381_fused_aggregate_verify_batch(
    const uint8_t* pks_compressed, size_t pk_stride,
    const uint8_t* sigs_compressed, size_t sig_stride,
    const uint8_t* msgs_flat, const uint64_t* msg_lens,
    size_t         n,
    const uint8_t* dst, size_t dst_len,
    uint8_t*       bitmap_out)
{
    return cevm::crypto::bls::fused_aggregate_verify_batch(
        pks_compressed, pk_stride,
        sigs_compressed, sig_stride,
        msgs_flat, msg_lens,
        n, dst, dst_len, bitmap_out);
}

extern "C" int bls12_381_fused_aggregate_verify_batch_aff(
    const uint8_t* pks_aff,  size_t pk_stride,
    const uint8_t* sigs_aff, size_t sig_stride,
    const uint8_t* msgs_flat, const uint64_t* msg_lens,
    size_t         n,
    const uint8_t* dst, size_t dst_len)
{
    return cevm::crypto::bls::fused_aggregate_verify_batch_aff(
        pks_aff, pk_stride,
        sigs_aff, sig_stride,
        msgs_flat, msg_lens,
        n, dst, dst_len);
}

// ============================================================================
// EIP-2537 precompile surface — Phase 5b closure.
// ============================================================================

extern "C" int bls12_381_g1_add(uint8_t rx[64], uint8_t ry[64],
                                const uint8_t x0[64], const uint8_t y0[64],
                                const uint8_t x1[64], const uint8_t y1[64])
{
    return cevm::crypto::bls::g1_add(rx, ry, x0, y0, x1, y1) ? 1 : 0;
}

extern "C" int bls12_381_g1_mul(uint8_t rx[64], uint8_t ry[64],
                                const uint8_t x[64], const uint8_t y[64],
                                const uint8_t c[32])
{
    return cevm::crypto::bls::g1_mul(rx, ry, x, y, c) ? 1 : 0;
}

extern "C" int bls12_381_g1_msm(uint8_t rx[64], uint8_t ry[64],
                                const uint8_t* xycs, size_t size)
{
    return cevm::crypto::bls::g1_msm(rx, ry, xycs, size) ? 1 : 0;
}

extern "C" int bls12_381_g2_add(uint8_t rx[128], uint8_t ry[128],
                                const uint8_t x0[128], const uint8_t y0[128],
                                const uint8_t x1[128], const uint8_t y1[128])
{
    return cevm::crypto::bls::g2_add(rx, ry, x0, y0, x1, y1) ? 1 : 0;
}

extern "C" int bls12_381_g2_mul(uint8_t rx[128], uint8_t ry[128],
                                const uint8_t x[128], const uint8_t y[128],
                                const uint8_t c[32])
{
    return cevm::crypto::bls::g2_mul(rx, ry, x, y, c) ? 1 : 0;
}

extern "C" int bls12_381_g2_msm(uint8_t rx[128], uint8_t ry[128],
                                const uint8_t* xycs, size_t size)
{
    return cevm::crypto::bls::g2_msm(rx, ry, xycs, size) ? 1 : 0;
}

extern "C" int bls12_381_pairing_check(uint8_t r[32],
                                       const uint8_t* pairs, size_t size)
{
    return cevm::crypto::bls::pairing_check(r, pairs, size) ? 1 : 0;
}

extern "C" int bls12_381_map_fp_to_g1(uint8_t rx[64], uint8_t ry[64],
                                      const uint8_t fp[64])
{
    return cevm::crypto::bls::map_fp_to_g1(rx, ry, fp) ? 1 : 0;
}

extern "C" int bls12_381_map_fp2_to_g2(uint8_t rx[128], uint8_t ry[128],
                                       const uint8_t fp2[128])
{
    return cevm::crypto::bls::map_fp2_to_g2(rx, ry, fp2) ? 1 : 0;
}

// C ABI -> C++ surface adapter for BLS12-381 pairing.

#include "c_bls_pairing.h"
#include "../cpp/bls_pairing.hpp"

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

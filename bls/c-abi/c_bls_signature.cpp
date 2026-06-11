// C ABI shim for IRTF BLS12-381 signature primitives. Forwards extern "C"
// entries to cevm::crypto::bls signature bodies in cpp/bls_signature.cpp.
// PRIVATE-linked into bls_signature_oracle (which links blst); production
// libbls_cpu.a / libcevm_precompiles.a stay blst-free per LP-137.

#include "c_bls_signature.h"
#include "../cpp/bls_signature.hpp"

extern "C" int bls12_381_keygen(const uint8_t seed[32], uint8_t sk[32])
{
    return cevm::crypto::bls::keygen(seed, sk);
}

extern "C" int bls12_381_sk_to_pk(const uint8_t sk[32], uint8_t pk[48])
{
    return cevm::crypto::bls::sk_to_pk(sk, pk);
}

extern "C" int bls12_381_sign(const uint8_t sk[32],
                              const uint8_t* msg, size_t msg_len,
                              uint8_t sig[96])
{
    return cevm::crypto::bls::sign(sk, msg, msg_len, sig);
}

extern "C" int bls12_381_verify(const uint8_t pk[48],
                                const uint8_t* msg, size_t msg_len,
                                const uint8_t sig[96])
{
    return cevm::crypto::bls::verify(pk, msg, msg_len, sig);
}

extern "C" int bls12_381_aggregate_pubkeys(const uint8_t* pks, size_t n,
                                           uint8_t agg_pk[48])
{
    return cevm::crypto::bls::aggregate_pubkeys(pks, n, agg_pk);
}

extern "C" int bls12_381_aggregate_sigs(const uint8_t* sigs, size_t n,
                                        uint8_t agg_sig[96])
{
    return cevm::crypto::bls::aggregate_sigs(sigs, n, agg_sig);
}

extern "C" int bls12_381_fast_aggregate_verify(const uint8_t* pks, size_t n,
                                               const uint8_t* msg, size_t msg_len,
                                               const uint8_t agg_sig[96])
{
    return cevm::crypto::bls::fast_aggregate_verify(pks, n, msg, msg_len, agg_sig);
}

extern "C" int bls12_381_aggregate_verify_distinct(const uint8_t* pks, size_t n,
                                                   const uint8_t* msgs_flat,
                                                   const size_t*  msg_lens,
                                                   const uint8_t  agg_sig[96])
{
    return cevm::crypto::bls::aggregate_verify_distinct(
        pks, n, msgs_flat, msg_lens, agg_sig);
}

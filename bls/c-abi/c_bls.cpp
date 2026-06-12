// Legacy bls_* surface (5-arg variants declared in <crypto.h>) wired through
// to the canonical bls12_381_* IRTF surface in c_bls_signature.cpp /
// c_bls_pairing.cpp. The body lives in cpp/bls_signature.cpp; this file is
// thin glue with no separate implementation, preserving the LP-137
// "first-party CPU canonical" invariant — there is exactly one BLS body in
// the library, and these aliases route to it.

// crypto.h declares the 5-arg bls_aggregate_verify (FastAggregateVerify
// shape) for ABI continuity; c_bls_pairing.h declares a different 3-arg
// shape (pairing-product). To avoid the C-level signature collision, this
// translation unit only sees crypto.h plus c_bls_signature.h and forward-
// declares the bls12_381_* primitives it needs from c_bls_signature.h.
//
// The 3-arg bls_aggregate_verify lives in c_bls_pairing.cpp (pairing
// product); we deliberately do NOT define a 5-arg bls_aggregate_verify
// here — callers that want FastAggregateVerify use the explicit
// bls_fast_aggregate_verify symbol below or bls12_381_fast_aggregate_verify
// directly.
#include "crypto.h"
#include "c_bls_signature.h"

extern "C" int bls_keygen(const uint8_t seed[32], uint8_t sk[32]) {
    if (seed == nullptr || sk == nullptr) return CRYPTO_ERR_INPUT;
    return bls12_381_keygen(seed, sk);
}

extern "C" int bls_sk_to_pk(const uint8_t sk[32], uint8_t pk[48]) {
    if (sk == nullptr || pk == nullptr) return CRYPTO_ERR_INPUT;
    return bls12_381_sk_to_pk(sk, pk);
}

extern "C" int bls_sign(const uint8_t sk[32],
                        const uint8_t* msg, size_t msg_len,
                        uint8_t sig[96]) {
    if (sk == nullptr || sig == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    return bls12_381_sign(sk, msg, msg_len, sig);
}

extern "C" int bls_verify(const uint8_t pk[48],
                          const uint8_t* msg, size_t msg_len,
                          const uint8_t sig[96]) {
    if (pk == nullptr || sig == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    return bls12_381_verify(pk, msg, msg_len, sig);
}

extern "C" int bls_aggregate_pubkeys(const uint8_t* pks, size_t n, uint8_t agg_pk[48]) {
    if (agg_pk == nullptr) return CRYPTO_ERR_INPUT;
    if (n > 0 && pks == nullptr) return CRYPTO_ERR_INPUT;
    return bls12_381_aggregate_pubkeys(pks, n, agg_pk);
}

extern "C" int bls_aggregate_sigs(const uint8_t* sigs, size_t n, uint8_t agg_sig[96]) {
    if (agg_sig == nullptr) return CRYPTO_ERR_INPUT;
    if (n > 0 && sigs == nullptr) return CRYPTO_ERR_INPUT;
    return bls12_381_aggregate_sigs(sigs, n, agg_sig);
}

// FastAggregateVerify (same-message-under-N-keys) is exposed as
// bls_fast_aggregate_verify (5-arg) to avoid colliding with the 3-arg
// pairing-product bls_aggregate_verify in c_bls_pairing.cpp. The 5-arg
// declaration in crypto.h:233 is documented as a FastAggregateVerify shape;
// callers needing that semantic should use bls_fast_aggregate_verify here
// or bls12_381_fast_aggregate_verify in c_bls_signature.h directly.
extern "C" int bls_fast_aggregate_verify(const uint8_t* pks, size_t n,
                                         const uint8_t* msg, size_t msg_len,
                                         const uint8_t agg_sig[96]) {
    if (n == 0 || pks == nullptr || agg_sig == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    return bls12_381_fast_aggregate_verify(pks, n, msg, msg_len, agg_sig);
}

// Distinct-message batch verify: N (pk_i, msg_i, sig_i) tuples.
extern "C" int bls_batch_verify(const uint8_t* pks, const uint8_t* msgs, size_t msg_len,
                                const uint8_t* sigs, size_t n) {
    if (n == 0) return CRYPTO_OK;
    if (pks == nullptr || sigs == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msgs == nullptr) return CRYPTO_ERR_INPUT;
    // Per-message verify loop. Production BLS batch verify uses a randomized
    // linear combination for amortized verification; that path is dispatched
    // through bls12_381_aggregate_verify_distinct which handles the batching.
    // For msg_len fixed across all N, lay out per-msg verify as a sequence.
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* pk_i  = pks  + i * 48;
        const uint8_t* msg_i = msgs + i * msg_len;
        const uint8_t* sig_i = sigs + i * 96;
        int r = bls12_381_verify(pk_i, msg_i, msg_len, sig_i);
        if (r != CRYPTO_OK) return r;
    }
    return CRYPTO_OK;
}

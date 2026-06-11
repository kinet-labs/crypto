// Phase 1 NOTIMPL stubs for the legacy bls_* C ABI declared in
// kinet-labs/crypto/c-abi/kinet_crypto.h.
//
// These names ship as part of libbls_cpu.a / libbls.a (kinet_add_algorithm)
// and stay blst-free per LP-137. The canonical IRTF signature primitives
// live at the bls12_381_* names in c_bls_signature.cpp, with the body in
// cpp/bls_signature.cpp (PRIVATE-linked into the test-time
// bls_signature_oracle archive).
//
// Phase 3 will lift these stubs to first-class CPU implementations in
// c_bls.cpp itself once the GPU dispatch layer lands. Until then, callers
// that need real signatures use the canonical bls12_381_* surface.

#include "crypto.h"

extern "C" int bls_keygen(const uint8_t /*seed*/[32], uint8_t /*sk*/[32]) {
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int bls_sk_to_pk(const uint8_t /*sk*/[32], uint8_t /*pk*/[48]) {
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int bls_sign(const uint8_t /*sk*/[32],
                        const uint8_t* /*msg*/, size_t /*msg_len*/,
                        uint8_t /*sig*/[96]) {
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int bls_verify(const uint8_t /*pk*/[48],
                          const uint8_t* /*msg*/, size_t /*msg_len*/,
                          const uint8_t /*sig*/[96]) {
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int bls_aggregate_pubkeys(const uint8_t* /*pks*/, size_t /*n*/, uint8_t /*agg_pk*/[48]) {
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int bls_aggregate_sigs(const uint8_t* /*sigs*/, size_t /*n*/, uint8_t /*agg_sig*/[96]) {
    return CRYPTO_ERR_NOTIMPL;
}

// Note: the 3-arg bls_aggregate_verify(pks, sigs, n) entry lives in
// c_bls_pairing.cpp (the WIRED pairing-product surface). The 5-arg form
// declared in kinet_crypto.h is FastAggregateVerify-shaped and currently
// has no production caller; if a Phase 3 caller appears, route it to
// bls12_381_fast_aggregate_verify in c_bls_signature.cpp.

extern "C" int bls_batch_verify(const uint8_t* /*pks*/, const uint8_t* /*msgs*/, size_t /*msg_len*/,
                                const uint8_t* /*sigs*/, size_t /*n*/) {
    return CRYPTO_ERR_NOTIMPL;
}

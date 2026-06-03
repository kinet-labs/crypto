// =============================================================================
// bls - BLS12-381 C ABI (Phase 1 stub)
// =============================================================================
// CPU body in cpp/bls.cpp links blst (vendored at cevm level only). Phase 3
// authors a first-class CPU implementation here. The legacy crypto.cpp at
// kinet-labs/crypto/src/crypto.cpp still implements kinet_crypto_bls_* with the old
// names; until Phase 4 wires consumers to the new symbols, both coexist.
// =============================================================================

#include "kinet_crypto.h"

extern "C" int kinet_bls_keygen(const uint8_t /*seed*/[32], uint8_t /*sk*/[32]) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_bls_sk_to_pk(const uint8_t /*sk*/[32], uint8_t /*pk*/[48]) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_bls_sign(const uint8_t /*sk*/[32],
                            const uint8_t* /*msg*/, size_t /*msg_len*/,
                            uint8_t /*sig*/[96]) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_bls_verify(const uint8_t /*pk*/[48],
                              const uint8_t* /*msg*/, size_t /*msg_len*/,
                              const uint8_t /*sig*/[96]) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_bls_aggregate_pubkeys(const uint8_t* /*pks*/, size_t /*n*/, uint8_t /*agg_pk*/[48]) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_bls_aggregate_sigs(const uint8_t* /*sigs*/, size_t /*n*/, uint8_t /*agg_sig*/[96]) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_bls_aggregate_verify(const uint8_t* /*pks*/, const uint8_t* /*msg*/, size_t /*msg_len*/,
                                        const uint8_t /*agg_sig*/[96], size_t /*n*/) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_bls_batch_verify(const uint8_t* /*pks*/, const uint8_t* /*msgs*/, size_t /*msg_len*/,
                                    const uint8_t* /*sigs*/, size_t /*n*/) {
    return KINET_ERR_NOTIMPL;
}

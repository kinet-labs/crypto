// =============================================================================
// kzg - C ABI (Phase 1 stub). cpp/kzg.cpp depends on blst trusted-setup data.
// =============================================================================

#include "kinet_crypto.h"

extern "C" int kinet_kzg_blob_to_commit(const uint8_t /*blob*/[131072], uint8_t /*commit*/[48]) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_kzg_commit_to_proof(const uint8_t /*blob*/[131072], const uint8_t /*z*/[32],
                                       uint8_t /*proof*/[48], uint8_t /*y*/[32]) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_kzg_verify_proof(const uint8_t /*commit*/[48], const uint8_t /*z*/[32],
                                    const uint8_t /*y*/[32], const uint8_t /*proof*/[48]) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_kzg_verify_blob(const uint8_t /*blob*/[131072],
                                   const uint8_t /*commit*/[48],
                                   const uint8_t /*proof*/[48]) {
    return KINET_ERR_NOTIMPL;
}

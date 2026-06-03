// =============================================================================
// secp256k1 - C ABI for the umbrella header
// =============================================================================
// The first-party body in cpp/ecrecover.cpp exports the canonical entry point
// kinet_secp256k1_ecrecover(hash, r, s, v, pubkey). This file maps the unified
// surface (kinet_secp256k1_recover, kinet_secp256k1_*) onto that body.
// =============================================================================

#include "kinet_crypto.h"
#include "kinet/crypto/secp256k1.h"

#include <cstring>

extern "C" int kinet_secp256k1_recover(const uint8_t msg32[32],
                                     const uint8_t sig[65],
                                     uint8_t pubkey[64]) {
    if (!msg32 || !sig || !pubkey) return KINET_ERR_INPUT;

    // sig is r(32) || s(32) || v(1).
    const uint8_t* r = sig;
    const uint8_t* s = sig + 32;
    uint8_t v        = sig[64];

    kinet_secp256k1_status st = kinet_secp256k1_ecrecover(msg32, r, s, v, pubkey);
    return st == KINET_SECP256K1_OK ? KINET_OK : KINET_ERR_VERIFY;
}

// Phase 3 wires up the remaining secp256k1 entry points (sign, verify,
// sk_to_pk). For now they advertise NOTIMPL so callers get a clear signal.
extern "C" int kinet_secp256k1_sign(const uint8_t /*sk*/[32],
                                  const uint8_t /*msg32*/[32],
                                  uint8_t /*sig*/[64],
                                  uint8_t* /*recid*/) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_secp256k1_verify(const uint8_t /*pk*/[64],
                                    const uint8_t /*msg32*/[32],
                                    const uint8_t /*sig*/[64]) {
    return KINET_ERR_NOTIMPL;
}

extern "C" int kinet_secp256k1_sk_to_pk(const uint8_t /*sk*/[32], uint8_t /*pk*/[64]) {
    return KINET_ERR_NOTIMPL;
}

// =============================================================================
// donna_bridge — isolation TU for kinet-labs/sr25519-crust calls
// =============================================================================
// kinet-labs/sr25519-crust v0.2.0+ supports the KINETFI_SR25519_NAMESPACE macro to
// prefix every public C symbol. We compile the donna sources with prefix
// `kinet_donna_` so the link-time symbol table contains only
// `kinet_donna_sr25519_sign` etc., never plain `sr25519_sign` -- preventing a
// collision with the brand-neutral C-ABI of the same name (which has a
// different argument shape) declared in <crypto.h>.
//
// donna_bridge.c re-declares the namespace before including sr25519.h so
// references in this TU resolve to the prefixed symbols emitted by the
// FetchContent build. The bridge's own helpers use the `kinet-labs_sr25519_`
// prefix to stay distinct from both the C-ABI surface and the renamed
// donna symbols.
// =============================================================================

#define KINETFI_SR25519_NAMESPACE kinet_donna_

#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "sr25519.h"

void kinet-labs_sr25519_sign_from_seed(uint8_t sig[64],
                                   const uint8_t seed[32],
                                   const uint8_t* msg,
                                   size_t msg_len) {
    sr25519_keypair kp;
    sr25519_keypair_from_seed(kp, seed);
    sr25519_sign(sig, kp + 64, kp, msg, (unsigned long)msg_len);
}

bool kinet-labs_sr25519_verify_seed(const uint8_t sig[64],
                                const uint8_t* msg,
                                size_t msg_len,
                                const uint8_t pk[32]) {
    return sr25519_verify(sig, msg, (unsigned long)msg_len, pk);
}

void kinet-labs_sr25519_keypair_from_seed(uint8_t keypair_96[96],
                                      const uint8_t seed[32]) {
    sr25519_keypair_from_seed(keypair_96, seed);
}

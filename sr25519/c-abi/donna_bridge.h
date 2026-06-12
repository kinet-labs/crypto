// =============================================================================
// donna_bridge.h — internal helpers wrapping kinet-labs/sr25519-crust
// =============================================================================
// `kinet-labs_sr25519_*` entry points so c_sr25519.cpp can call into the donna
// implementation without dragging the donna sr25519.h into a TU that also
// includes the kinet-labs C-ABI <crypto.h> (which declares sr25519_sign /
// sr25519_verify with the brand-neutral 32-byte-seed signatures).
// =============================================================================

#ifndef KINETCPP_CRYPTO_SR25519_DONNA_BRIDGE_H_
#define KINETCPP_CRYPTO_SR25519_DONNA_BRIDGE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Sign `msg` under the keypair derived from `seed`. Output 64-byte sig.
void kinet-labs_sr25519_sign_from_seed(uint8_t sig[64],
                                   const uint8_t seed[32],
                                   const uint8_t* msg,
                                   size_t msg_len);

// Verify a 64-byte sig against `pk` and `msg`. Returns true iff valid.
bool kinet-labs_sr25519_verify_seed(const uint8_t sig[64],
                                const uint8_t* msg,
                                size_t msg_len,
                                const uint8_t pk[32]);

// Derive 96-byte donna keypair [secret(32)|nonce(32)|public(32)] from seed.
// Used by tests to assert the Substrate //Alice public-key KAT.
void kinet-labs_sr25519_keypair_from_seed(uint8_t keypair_96[96],
                                      const uint8_t seed[32]);

#ifdef __cplusplus
}
#endif

#endif  // KINETCPP_CRYPTO_SR25519_DONNA_BRIDGE_H_

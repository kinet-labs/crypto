/*
 * Keccak-256 (Ethereum hash). First-party implementation per Keccak Reference
 * v3.0 (Bertoni-Daemen-Peeters-Van Assche) -- the pre-FIPS-202 padding scheme
 * with delimiter 0x01 used by Ethereum, NOT the FIPS-202 SHA3-256 padding
 * (which uses 0x06).
 *
 * No external dependencies. Pure portable C.
 */
#ifndef KINET_CRYPTO_KECCAK_H
#define KINET_CRYPTO_KECCAK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Keccak-256: input -> 32-byte digest. */
void keccak256(const uint8_t* input, size_t input_len, uint8_t out[32]);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* KINET_CRYPTO_KECCAK_H */

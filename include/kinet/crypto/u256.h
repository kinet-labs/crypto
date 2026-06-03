/* Copyright (c) 2024-2026 Kinet Industries Inc.
 * SPDX-License-Identifier: BSD-3-Clause-Eco
 *
 * Internal 256-bit unsigned integer type used by kinet_crypto field arithmetic.
 * Header-only, public layout so GPU drivers can share buffer formats.
 *
 * Layout: 4 x uint64_t little-endian limbs. limbs[0] = least significant.
 *
 * This is intentionally minimal; per-curve modular arithmetic lives next to
 * each algorithm under src/<alg>/.
 */
#ifndef KINET_CRYPTO_U256_H
#define KINET_CRYPTO_U256_H

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t limbs[4];
} kinet_u256;

static inline void kinet_u256_zero(kinet_u256* a) {
    a->limbs[0] = 0; a->limbs[1] = 0; a->limbs[2] = 0; a->limbs[3] = 0;
}

static inline int kinet_u256_is_zero(const kinet_u256* a) {
    return (a->limbs[0] | a->limbs[1] | a->limbs[2] | a->limbs[3]) == 0;
}

static inline int kinet_u256_cmp(const kinet_u256* a, const kinet_u256* b) {
    for (int i = 3; i >= 0; --i) {
        if (a->limbs[i] < b->limbs[i]) return -1;
        if (a->limbs[i] > b->limbs[i]) return 1;
    }
    return 0;
}

/* Big-endian 32-byte load */
static inline void kinet_u256_from_be32(kinet_u256* r, const uint8_t bytes[32]) {
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t v = 0;
        const int base = (3 - limb) * 8;
        for (int b = 0; b < 8; ++b) {
            v = (v << 8) | (uint64_t)bytes[base + b];
        }
        r->limbs[limb] = v;
    }
}

/* Big-endian 32-byte store */
static inline void kinet_u256_to_be32(uint8_t bytes[32], const kinet_u256* a) {
    for (int limb = 0; limb < 4; ++limb) {
        const int base = (3 - limb) * 8;
        uint64_t v = a->limbs[limb];
        for (int b = 7; b >= 0; --b) {
            bytes[base + b] = (uint8_t)(v & 0xFF);
            v >>= 8;
        }
    }
}

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* KINET_CRYPTO_U256_H */

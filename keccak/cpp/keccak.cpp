// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// First-party Keccak-256 (Ethereum hash) implementation.
//
// Reference: Keccak v3.0 specification by Bertoni-Daemen-Peeters-Van Assche.
//
// Parameters for Keccak-256 as used by Ethereum:
//   * permutation: Keccak-f[1600], 24 rounds
//   * rate r = 1088 bits = 136 bytes
//   * capacity c = 512 bits = 64 bytes
//   * digest = 256 bits = 32 bytes
//   * padding: pad10*1 with delimiter 0x01 (NOT 0x06 / SHA-3 FIPS 202)
//
// All constants below are derived from the spec, not from any other library.

#include "kinet/crypto/keccak.h"
#include <cstring>
#include <cstdint>

namespace {

// Keccak round constants (the 24 RC values for f[1600]).
// Computed by the LFSR procedure in Keccak Reference §1.2.
constexpr uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

// Rotation offsets r[x][y]. Per Keccak Reference Table 2.
constexpr int R[5][5] = {
    {  0,  36,   3, 105, 210}, // x=0
    {  1, 300,  10,  45,  66}, // x=1
    { 190,   6, 171,  15, 253}, // x=2
    { 28,  55, 153,  21, 120}, // x=3
    { 91, 276, 231, 136,  78}, // x=4
};
// All entries reduced mod 64 (since lanes are 64-bit).

inline uint64_t rotl64(uint64_t x, int n) {
    n &= 63;
    if (n == 0) return x;
    return (x << n) | (x >> (64 - n));
}

inline void keccakf1600(uint64_t state[25]) {
    uint64_t* a = state;
    uint64_t C[5];
    uint64_t D[5];
    uint64_t B[25];

    for (int round = 0; round < 24; ++round) {
        // theta
        for (int x = 0; x < 5; ++x) {
            C[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for (int x = 0; x < 5; ++x) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                a[x + 5 * y] ^= D[x];
            }
        }

        // rho + pi
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                int new_x = y;
                int new_y = (2 * x + 3 * y) % 5;
                B[new_x + 5 * new_y] = rotl64(a[x + 5 * y], R[x][y] % 64);
            }
        }

        // chi
        for (int y = 0; y < 5; ++y) {
            uint64_t row[5];
            for (int x = 0; x < 5; ++x) row[x] = B[x + 5 * y];
            for (int x = 0; x < 5; ++x) {
                a[x + 5 * y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }

        // iota
        a[0] ^= RC[round];
    }
}

inline uint64_t load64_le(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

inline void store64_le(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i));
}

}  // namespace

extern "C" void keccak256(const uint8_t* input, size_t input_len, uint8_t out[32]) {
    constexpr int RATE = 136;       // bytes per absorb block
    constexpr int OUT_LEN = 32;

    uint64_t state[25];
    std::memset(state, 0, sizeof(state));

    // Absorb full blocks
    size_t i = 0;
    while (input_len - i >= (size_t)RATE) {
        for (int j = 0; j < RATE / 8; ++j) {
            state[j] ^= load64_le(input + i + j * 8);
        }
        keccakf1600(state);
        i += RATE;
    }

    // Final block: copy remaining + pad10*1 with delimiter 0x01.
    uint8_t block[RATE];
    std::memset(block, 0, RATE);
    size_t rem = input_len - i;
    if (rem) std::memcpy(block, input + i, rem);
    block[rem] = 0x01;             // Keccak (Ethereum) delimiter
    block[RATE - 1] |= 0x80;       // final bit of pad10*1
    for (int j = 0; j < RATE / 8; ++j) {
        state[j] ^= load64_le(block + j * 8);
    }
    keccakf1600(state);

    // Squeeze 32 bytes
    for (int j = 0; j < OUT_LEN / 8; ++j) {
        store64_le(out + j * 8, state[j]);
    }
}

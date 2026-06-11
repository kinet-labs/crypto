// RIPEMD-160 batch hashing — CUDA implementation.
// Byte-equal to ripemd160/cpp/ripemd160.cpp::ripemd160() and to
// ripemd160/gpu/metal/ripemd160_batch.metal::ripemd160_jobs.
//
// Algorithm: Dobbertin, Bosselaers, Preneel — "RIPEMD-160: A Strengthened
// Version of RIPEMD" (1996). Two parallel "lines" (left + right) of 5 rounds
// each, 16 step operations per round, applied to a 16-word LE block. Final
// state combination interleaves left-line z[0] and right-line z[1] across
// the IV plus a 4-word rotation. Padding is MD4-style: append 0x80, zero-pad
// to 56 mod 64, append 64-bit little-endian bit length.
//
// One thread per input. Layout matches the Metal/SHA-256 drivers: caller
// fills a flat byte arena and per-input (offset, length) descriptors;
// outputs are 20-byte stride.

#include <cstdint>

#ifndef __CUDA_ARCH__
#define __device__
#define __global__
#define __shared__
struct dim3 { unsigned x, y, z; };
static dim3 blockIdx, blockDim, threadIdx;
#endif

// Round added constants (Dobbertin §3, Table 1). K[i] for left line, K'[i]
// for right line. Both lines have 5 rounds; only one is non-zero per round
// per line.
__device__ static const uint32_t K0[5] = {
    0x00000000u, 0x5a827999u, 0x6ed9eba1u, 0x8f1bbcdcu, 0xa953fd4eu
};
__device__ static const uint32_t K1[5] = {
    0x50a28be6u, 0x5c4dd124u, 0x6d703ef3u, 0x7a6d76e9u, 0x00000000u
};

// Message word selection r[i] (left) and r'[i] (right). 80 indices each.
__device__ static const uint8_t R0[80] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
     3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
     1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
     4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13,
};
__device__ static const uint8_t R1[80] = {
     5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
     6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
    15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
     8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
    12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11,
};

// Rotation amounts s[i] / s'[i].
__device__ static const uint8_t S0[80] = {
    11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
     7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
    11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
    11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
     9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6,
};
__device__ static const uint8_t S1[80] = {
     8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
     9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
     9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
    15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
     8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11,
};

__device__ static inline uint32_t rotl32(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32u - n));
}

// Boolean selection functions f_j (Dobbertin §3, eq. 1-5).
__device__ static inline uint32_t round_f(uint32_t round_idx,
                                           uint32_t x, uint32_t y, uint32_t z) {
    if (round_idx == 0) return x ^ y ^ z;                  // f1
    if (round_idx == 1) return ((y ^ z) & x) ^ z;          // f2 = (x&y) | (~x&z)
    if (round_idx == 2) return (x | ~y) ^ z;               // f3
    if (round_idx == 3) return ((x ^ y) & z) ^ y;          // f4 = (x&z) | (y&~z)
    return x ^ (y | ~z);                                    // f5
}

__device__ static void compress(uint32_t* h, const uint32_t* w) {
    // Two parallel lines z[0] (uses f1..f5 in order, R0/S0/K0) and z[1]
    // (uses f5..f1 mirrored, R1/S1/K1).
    uint32_t a0 = h[0], b0 = h[1], c0 = h[2], d0 = h[3], e0 = h[4];
    uint32_t a1 = h[0], b1 = h[1], c1 = h[2], d1 = h[3], e1 = h[4];

    for (uint32_t j = 0; j < 80; ++j) {
        uint32_t round_idx = j / 16u;

        // Left line.
        uint32_t t0 = rotl32(a0 + round_f(round_idx, b0, c0, d0)
                              + w[R0[j]] + K0[round_idx], S0[j]) + e0;
        a0 = e0; e0 = d0; d0 = rotl32(c0, 10); c0 = b0; b0 = t0;

        // Right line uses mirrored function index 4 - round_idx.
        uint32_t inv_round = 4u - round_idx;
        uint32_t t1 = rotl32(a1 + round_f(inv_round, b1, c1, d1)
                              + w[R1[j]] + K1[round_idx], S1[j]) + e1;
        a1 = e1; e1 = d1; d1 = rotl32(c1, 10); c1 = b1; b1 = t1;
    }

    // Final mixdown: t = h[1] + c0 + d1, h[1] = h[2] + d0 + e1, ...
    uint32_t t = h[1] + c0 + d1;
    h[1] = h[2] + d0 + e1;
    h[2] = h[3] + e0 + a1;
    h[3] = h[4] + a0 + b1;
    h[4] = h[0] + b0 + c1;
    h[0] = t;
}

extern "C" __global__ void ripemd160_jobs(
    const uint8_t*  __restrict__ inputs,
    const uint32_t* __restrict__ input_offsets,
    const uint32_t* __restrict__ input_lens,
    uint8_t*        __restrict__ outputs,
    uint32_t                     num_jobs)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= num_jobs) return;

    const uint8_t* in = inputs + input_offsets[tid];
    uint32_t len = input_lens[tid];

    uint32_t h[5] = {
        0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u
    };

    uint8_t block[64];
    uint32_t w[16];
    uint32_t pos = 0;
    while ((len - pos) >= 64u) {
        for (uint32_t i = 0; i < 64; ++i) block[i] = in[pos + i];
        for (uint32_t i = 0; i < 16; ++i) {
            w[i] = ((uint32_t)block[i * 4 + 0]      ) |
                   ((uint32_t)block[i * 4 + 1] <<  8) |
                   ((uint32_t)block[i * 4 + 2] << 16) |
                   ((uint32_t)block[i * 4 + 3] << 24);
        }
        compress(h, w);
        pos += 64;
    }

    // Final block(s) with MD4-style padding: append 0x80, zero-pad, 64-bit LE
    // bit length at offset 56..63 of the final 64-byte block.
    uint32_t rem = len - pos;
    for (uint32_t i = 0; i < 64; ++i) block[i] = 0;
    for (uint32_t i = 0; i < rem; ++i) block[i] = in[pos + i];
    block[rem] = 0x80u;

    if (rem >= 56u) {
        // Tail spans two final blocks.
        for (uint32_t i = 0; i < 16; ++i) {
            w[i] = ((uint32_t)block[i * 4 + 0]      ) |
                   ((uint32_t)block[i * 4 + 1] <<  8) |
                   ((uint32_t)block[i * 4 + 2] << 16) |
                   ((uint32_t)block[i * 4 + 3] << 24);
        }
        compress(h, w);
        for (uint32_t i = 0; i < 64; ++i) block[i] = 0;
    }

    uint64_t bit_len = (uint64_t)len * 8u;
    block[56] = (uint8_t)((bit_len      ) & 0xFFu);
    block[57] = (uint8_t)((bit_len >>  8) & 0xFFu);
    block[58] = (uint8_t)((bit_len >> 16) & 0xFFu);
    block[59] = (uint8_t)((bit_len >> 24) & 0xFFu);
    block[60] = (uint8_t)((bit_len >> 32) & 0xFFu);
    block[61] = (uint8_t)((bit_len >> 40) & 0xFFu);
    block[62] = (uint8_t)((bit_len >> 48) & 0xFFu);
    block[63] = (uint8_t)((bit_len >> 56) & 0xFFu);

    for (uint32_t i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i * 4 + 0]      ) |
               ((uint32_t)block[i * 4 + 1] <<  8) |
               ((uint32_t)block[i * 4 + 2] << 16) |
               ((uint32_t)block[i * 4 + 3] << 24);
    }
    compress(h, w);

    uint8_t* out = outputs + tid * 20;
    for (uint32_t i = 0; i < 5; ++i) {
        out[i * 4 + 0] = (uint8_t)( h[i]        & 0xFFu);
        out[i * 4 + 1] = (uint8_t)((h[i] >>  8) & 0xFFu);
        out[i * 4 + 2] = (uint8_t)((h[i] >> 16) & 0xFFu);
        out[i * 4 + 3] = (uint8_t)((h[i] >> 24) & 0xFFu);
    }
}

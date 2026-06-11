// GPU-batched RIPEMD-160 (Dobbertin et al. 1996). One thread per input.
// Byte-equal to ripemd160/cpp/ripemd160.cpp::ripemd160().
//
// 64-byte blocks (16 LE uint32 words), 5 rounds × 16 steps × 2 parallel
// lines (z0/z1), output 20 bytes little-endian. Padding is MD4-style:
// append 0x80, zero pad to 56 mod 64, append 64-bit little-endian bit-length.

#include <metal_stdlib>
using namespace metal;

constant uint K0[5] = { 0x00000000u, 0x5a827999u, 0x6ed9eba1u, 0x8f1bbcdcu, 0xa953fd4eu };
constant uint K1[5] = { 0x50a28be6u, 0x5c4dd124u, 0x6d703ef3u, 0x7a6d76e9u, 0x00000000u };

constant uint8_t R0[80] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
     3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
     1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
     4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13,
};
constant uint8_t R1[80] = {
     5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
     6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
    15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
     8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
    12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11,
};
constant uint8_t S0[80] = {
    11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
     7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
    11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
    11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
     9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6,
};
constant uint8_t S1[80] = {
     8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
     9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
     9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
    15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
     8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11,
};

inline uint rotl32(uint x, uint n) { return (x << n) | (x >> (32u - n)); }

inline uint f1(uint x, uint y, uint z) { return x ^ y ^ z; }
inline uint f2(uint x, uint y, uint z) { return ((y ^ z) & x) ^ z; }       // (x&y) | (~x&z)
inline uint f3(uint x, uint y, uint z) { return (x | ~y) ^ z; }
inline uint f4(uint x, uint y, uint z) { return ((x ^ y) & z) ^ y; }       // (x&z) | (y&~z)
inline uint f5(uint x, uint y, uint z) { return x ^ (y | ~z); }

inline uint round_f(uint round_idx, uint x, uint y, uint z) {
    if (round_idx == 0) return f1(x, y, z);
    if (round_idx == 1) return f2(x, y, z);
    if (round_idx == 2) return f3(x, y, z);
    if (round_idx == 3) return f4(x, y, z);
    return f5(x, y, z);
}

inline void compress(thread uint* h, thread const uint* w) {
    // Two parallel lines z0 (uses R0/S0/K0/f1..f5) and z1 (uses R1/S1/K1/f5..f1).
    uint a0 = h[0], b0 = h[1], c0 = h[2], d0 = h[3], e0 = h[4];
    uint a1 = h[0], b1 = h[1], c1 = h[2], d1 = h[3], e1 = h[4];

    for (uint j = 0; j < 80; ++j) {
        uint round_idx = j / 16u;

        // Line 0
        uint t0 = rotl32(a0 + round_f(round_idx, b0, c0, d0)
                            + w[R0[j]] + K0[round_idx], S0[j]) + e0;
        a0 = e0; e0 = d0; d0 = rotl32(c0, 10); c0 = b0; b0 = t0;

        // Line 1: function index is 4 - round_idx (mirror).
        uint inv_round = 4u - round_idx;
        uint t1 = rotl32(a1 + round_f(inv_round, b1, c1, d1)
                            + w[R1[j]] + K1[round_idx], S1[j]) + e1;
        a1 = e1; e1 = d1; d1 = rotl32(c1, 10); c1 = b1; b1 = t1;
    }

    uint t = h[1] + c0 + d1;
    h[1] = h[2] + d0 + e1;
    h[2] = h[3] + e0 + a1;
    h[3] = h[4] + a0 + b1;
    h[4] = h[0] + b0 + c1;
    h[0] = t;
}

struct Ripemd160JobGPU {
    uint input_offset;
    uint input_len;
    uint output_offset;
    uint _pad;
};

kernel void ripemd160_jobs(
    device const Ripemd160JobGPU* jobs    [[buffer(0)]],
    device const uchar*           inputs  [[buffer(1)]],
    device       uchar*           outputs [[buffer(2)]],
    constant uint& num_jobs               [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= num_jobs) return;

    Ripemd160JobGPU j = jobs[tid];
    const device uchar* in = inputs + j.input_offset;
    device uchar* out = outputs + j.output_offset;

    uint h[5] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u };

    // Process full 64-byte blocks.
    uchar block[64];
    uint w[16];
    uint pos = 0;
    while ((j.input_len - pos) >= 64u) {
        for (uint i = 0; i < 64; ++i) block[i] = in[pos + i];
        for (uint i = 0; i < 16; ++i) {
            w[i] = (uint(block[i * 4 + 0])      ) |
                   (uint(block[i * 4 + 1]) <<  8) |
                   (uint(block[i * 4 + 2]) << 16) |
                   (uint(block[i * 4 + 3]) << 24);
        }
        compress(h, w);
        pos += 64;
    }

    // Final block(s) with MD4-style padding.
    uint rem = j.input_len - pos;
    for (uint i = 0; i < 64; ++i) block[i] = 0;
    for (uint i = 0; i < rem; ++i) block[i] = in[pos + i];
    block[rem] = 0x80u;

    if (rem >= 56u) {
        // Tail spans two final blocks.
        for (uint i = 0; i < 16; ++i) {
            w[i] = (uint(block[i * 4 + 0])      ) |
                   (uint(block[i * 4 + 1]) <<  8) |
                   (uint(block[i * 4 + 2]) << 16) |
                   (uint(block[i * 4 + 3]) << 24);
        }
        compress(h, w);
        for (uint i = 0; i < 64; ++i) block[i] = 0;
    }

    // Append 64-bit little-endian bit length at offset 56..63.
    ulong bit_len = (ulong)j.input_len * 8u;
    block[56] = uchar((bit_len      ) & 0xFF);
    block[57] = uchar((bit_len >>  8) & 0xFF);
    block[58] = uchar((bit_len >> 16) & 0xFF);
    block[59] = uchar((bit_len >> 24) & 0xFF);
    block[60] = uchar((bit_len >> 32) & 0xFF);
    block[61] = uchar((bit_len >> 40) & 0xFF);
    block[62] = uchar((bit_len >> 48) & 0xFF);
    block[63] = uchar((bit_len >> 56) & 0xFF);

    for (uint i = 0; i < 16; ++i) {
        w[i] = (uint(block[i * 4 + 0])      ) |
               (uint(block[i * 4 + 1]) <<  8) |
               (uint(block[i * 4 + 2]) << 16) |
               (uint(block[i * 4 + 3]) << 24);
    }
    compress(h, w);

    // Output little-endian.
    for (uint i = 0; i < 5; ++i) {
        out[i * 4 + 0] = uchar( h[i]        & 0xFF);
        out[i * 4 + 1] = uchar((h[i] >>  8) & 0xFF);
        out[i * 4 + 2] = uchar((h[i] >> 16) & 0xFF);
        out[i * 4 + 3] = uchar((h[i] >> 24) & 0xFF);
    }
}

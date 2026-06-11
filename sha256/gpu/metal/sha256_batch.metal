// GPU-batched SHA-256 (FIPS 180-4). One thread per input. Byte-equal to
// sha256/cpp/sha256.cpp::sha256() for arbitrary-length inputs.
//
// Layout: caller fills a Sha256Job[] with (input_offset, input_len,
// output_offset). Inputs share a flat byte arena; outputs share a 32-byte
// stride arena. Padding is canonical (FIPS 180-4 sec 5.1.1): append 0x80, then
// zero pad to 64 mod 56, then 8-byte big-endian bit length.

#include <metal_stdlib>
using namespace metal;

// FIPS 180-4 round constants (first 32 bits of fractional parts of cube roots
// of the first 64 primes).
constant uint K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

inline uint rotr32(uint x, uint n) { return (x >> n) | (x << (32 - n)); }

inline void sha256_block(thread uint* h, thread const uchar* p) {
    uint w[64];
    for (uint i = 0; i < 16; ++i) {
        w[i] = (uint(p[i * 4 + 0]) << 24) |
               (uint(p[i * 4 + 1]) << 16) |
               (uint(p[i * 4 + 2]) <<  8) |
               (uint(p[i * 4 + 3]));
    }
    for (uint i = 16; i < 64; ++i) {
        uint s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint s1 = rotr32(w[i -  2], 17) ^ rotr32(w[i -  2], 19) ^ (w[i -  2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint a = h[0], b = h[1], c = h[2], d = h[3];
    uint e = h[4], f = h[5], g = h[6], hh = h[7];

    for (uint i = 0; i < 64; ++i) {
        uint S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint ch = (e & f) ^ ((~e) & g);
        uint t1 = hh + S1 + ch + K[i] + w[i];
        uint S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint mj = (a & b) ^ (a & c) ^ (b & c);
        uint t2 = S0 + mj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

struct Sha256JobGPU {
    uint input_offset;
    uint input_len;
    uint output_offset;
    uint _pad;
};

kernel void sha256_jobs(
    device const Sha256JobGPU* jobs    [[buffer(0)]],
    device const uchar*        inputs  [[buffer(1)]],
    device       uchar*        outputs [[buffer(2)]],
    constant uint& num_jobs            [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= num_jobs) return;

    Sha256JobGPU j = jobs[tid];
    const device uchar* in = inputs + j.input_offset;
    device uchar* out = outputs + j.output_offset;

    // FIPS 180-4 IV.
    uint h[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    };

    // Process full 64-byte blocks streaming from device memory.
    uchar block[64];
    uint absorbed = 0;
    while (j.input_len - absorbed >= 64) {
        for (uint i = 0; i < 64; ++i) block[i] = in[absorbed + i];
        sha256_block(h, block);
        absorbed += 64;
    }

    // Final block(s): copy tail, append 0x80, pad zero, append 64-bit
    // big-endian bit length. May span one or two blocks.
    uint rem = j.input_len - absorbed;
    for (uint i = 0; i < 64; ++i) block[i] = 0;
    for (uint i = 0; i < rem; ++i) block[i] = in[absorbed + i];
    block[rem] = 0x80u;

    if (rem >= 56) {
        // Tail spans two final blocks.
        sha256_block(h, block);
        for (uint i = 0; i < 64; ++i) block[i] = 0;
    }

    ulong bit_len = (ulong)j.input_len * 8u;
    block[56] = uchar((bit_len >> 56) & 0xFF);
    block[57] = uchar((bit_len >> 48) & 0xFF);
    block[58] = uchar((bit_len >> 40) & 0xFF);
    block[59] = uchar((bit_len >> 32) & 0xFF);
    block[60] = uchar((bit_len >> 24) & 0xFF);
    block[61] = uchar((bit_len >> 16) & 0xFF);
    block[62] = uchar((bit_len >>  8) & 0xFF);
    block[63] = uchar( bit_len        & 0xFF);
    sha256_block(h, block);

    // Output big-endian.
    for (uint i = 0; i < 8; ++i) {
        out[i * 4 + 0] = uchar((h[i] >> 24) & 0xFF);
        out[i * 4 + 1] = uchar((h[i] >> 16) & 0xFF);
        out[i * 4 + 2] = uchar((h[i] >>  8) & 0xFF);
        out[i * 4 + 3] = uchar( h[i]        & 0xFF);
    }
}

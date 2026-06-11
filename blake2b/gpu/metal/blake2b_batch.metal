// GPU-batched BLAKE2b-512 (RFC 7693). One thread per input. Byte-equal to
// blake2b/c-abi/blake2b_full.cpp::hash() — no key, no salt, no personalisation.
//
// 12 rounds, 128-byte blocks, 64-byte digest. Counter `t` increments by
// the actual amount consumed (per RFC 7693 sec 3.3). Final block flag set
// on the last call.

#include <metal_stdlib>
using namespace metal;

constant ulong IV[8] = {
    0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
    0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
    0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
    0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL,
};

constant uint8_t SIGMA[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
};

inline ulong rotr64(ulong x, uint n) { return (x >> n) | (x << (64u - n)); }

inline void g_mix(thread ulong* v, uint a, uint b, uint c, uint d,
                  ulong x, ulong y) {
    v[a] = v[a] + v[b] + x;
    v[d] = rotr64(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];
    v[b] = rotr64(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y;
    v[d] = rotr64(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = rotr64(v[b] ^ v[c], 63);
}

inline void blake2b_compress(thread ulong* h, thread const ulong* m,
                             ulong t0, ulong t1, bool last) {
    ulong v[16];
    for (uint i = 0; i < 8; ++i) v[i]     = h[i];
    for (uint i = 0; i < 8; ++i) v[i + 8] = IV[i];
    v[12] ^= t0;
    v[13] ^= t1;
    if (last) v[14] = ~v[14];

    for (uint i = 0; i < 12; ++i) {
        const constant uint8_t* s = SIGMA[i % 10];
        g_mix(v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
        g_mix(v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
        g_mix(v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
        g_mix(v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);
        g_mix(v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
        g_mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g_mix(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        g_mix(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }

    for (uint i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[i + 8];
}

struct Blake2bJobGPU {
    uint input_offset;
    uint input_len;
    uint output_offset;
    uint _pad;
};

kernel void blake2b_jobs(
    device const Blake2bJobGPU* jobs    [[buffer(0)]],
    device const uchar*         inputs  [[buffer(1)]],
    device       uchar*         outputs [[buffer(2)]],
    constant uint& num_jobs             [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= num_jobs) return;

    Blake2bJobGPU j = jobs[tid];
    const device uchar* in = inputs + j.input_offset;
    device uchar* out = outputs + j.output_offset;

    // Param block sec 2.5: digest_len=64, key_len=0, fanout=1, depth=1.
    // h[0] ^= 0x01010040 (= 0x01010000 ^ 64).
    ulong h[8];
    for (uint i = 0; i < 8; ++i) h[i] = IV[i];
    h[0] ^= 0x0000000001010040UL;

    // Stream: process all but the final block as non-last.
    ulong t0 = 0, t1 = 0;
    ulong m[16];
    uchar block[128];
    uint pos = 0;

    while ((j.input_len - pos) > 128u) {
        for (uint i = 0; i < 128; ++i) block[i] = in[pos + i];
        for (uint i = 0; i < 16; ++i) {
            ulong w = 0;
            for (uint b = 0; b < 8; ++b)
                w |= ulong(block[i * 8 + b]) << (b * 8);
            m[i] = w;
        }
        pos += 128;
        ulong t0_new = t0 + 128;
        if (t0_new < t0) ++t1;
        t0 = t0_new;
        blake2b_compress(h, m, t0, t1, false);
    }

    // Final (possibly partial) block, zero-padded.
    uint rem = j.input_len - pos;
    for (uint i = 0; i < 128; ++i) block[i] = 0;
    for (uint i = 0; i < rem; ++i) block[i] = in[pos + i];
    for (uint i = 0; i < 16; ++i) {
        ulong w = 0;
        for (uint b = 0; b < 8; ++b)
            w |= ulong(block[i * 8 + b]) << (b * 8);
        m[i] = w;
    }
    ulong t0_new = t0 + (ulong)rem;
    if (t0_new < t0) ++t1;
    t0 = t0_new;
    blake2b_compress(h, m, t0, t1, true);

    // Little-endian output.
    for (uint i = 0; i < 8; ++i) {
        for (uint b = 0; b < 8; ++b) {
            out[i * 8 + b] = uchar((h[i] >> (b * 8)) & 0xFF);
        }
    }
}

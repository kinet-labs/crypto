// SHA-256 batch hashing — CUDA implementation.
// Matches sha256/cpp/sha256.cpp::sha256() and sha256/gpu/metal/sha256_batch.metal
// byte-for-byte (FIPS 180-4). One thread per input.
//
// Layout matches the Metal driver: caller fills a Sha256Job[] with
// (input_offset, input_len, output_offset). Inputs share a flat byte arena;
// outputs share a 32-byte stride arena. Padding is canonical (FIPS 180-4
// sec 5.1.1): append 0x80, then zero pad to 64 mod 56, then 8-byte
// big-endian bit length.

#include <cstdint>

#ifndef __CUDA_ARCH__
#define __device__
#define __global__
#define __shared__
struct dim3 { unsigned x, y, z; };
static dim3 blockIdx, blockDim, threadIdx;
#endif

// FIPS 180-4 round constants (§4.2.2): first 32 bits of the fractional parts
// of the cube roots of the first 64 primes 2..311.
__device__ static const uint32_t K[64] = {
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

__device__ static inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32u - n));
}

__device__ static inline void sha256_block(uint32_t* h, const uint8_t* p) {
    uint32_t w[64];
    #pragma unroll
    for (uint32_t i = 0; i < 16; ++i) {
        w[i] = (uint32_t(p[i * 4 + 0]) << 24) |
               (uint32_t(p[i * 4 + 1]) << 16) |
               (uint32_t(p[i * 4 + 2]) <<  8) |
               (uint32_t(p[i * 4 + 3]));
    }
    #pragma unroll
    for (uint32_t i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i -  2], 17) ^ rotr32(w[i -  2], 19) ^ (w[i -  2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

    #pragma unroll
    for (uint32_t i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

extern "C" __global__ void sha256_jobs(
    const uint8_t*  __restrict__ inputs,
    const uint32_t* __restrict__ input_offsets,
    const uint32_t* __restrict__ input_lens,
    uint8_t*        __restrict__ outputs,
    uint32_t num_jobs)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= num_jobs) return;

    const uint8_t* in = inputs + input_offsets[tid];
    uint8_t* out = outputs + tid * 32u;
    uint32_t len = input_lens[tid];

    // FIPS 180-4 IV (§5.3.3): first 32 bits of fractional parts of the square
    // roots of the first 8 primes 2..19.
    uint32_t h[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    };

    // Process full 64-byte blocks streaming from device memory.
    uint8_t block[64];
    uint32_t absorbed = 0;
    while (len - absorbed >= 64u) {
        #pragma unroll
        for (uint32_t i = 0; i < 64u; ++i) block[i] = in[absorbed + i];
        sha256_block(h, block);
        absorbed += 64u;
    }

    // Final block(s): copy tail, append 0x80, pad zero, append 64-bit
    // big-endian bit length. May span one or two blocks.
    uint32_t rem = len - absorbed;
    #pragma unroll
    for (uint32_t i = 0; i < 64u; ++i) block[i] = 0;
    for (uint32_t i = 0; i < rem; ++i) block[i] = in[absorbed + i];
    block[rem] = 0x80u;

    if (rem >= 56u) {
        // Tail spans two final blocks.
        sha256_block(h, block);
        #pragma unroll
        for (uint32_t i = 0; i < 64u; ++i) block[i] = 0;
    }

    uint64_t bit_len = uint64_t(len) * 8u;
    block[56] = uint8_t((bit_len >> 56) & 0xFFu);
    block[57] = uint8_t((bit_len >> 48) & 0xFFu);
    block[58] = uint8_t((bit_len >> 40) & 0xFFu);
    block[59] = uint8_t((bit_len >> 32) & 0xFFu);
    block[60] = uint8_t((bit_len >> 24) & 0xFFu);
    block[61] = uint8_t((bit_len >> 16) & 0xFFu);
    block[62] = uint8_t((bit_len >>  8) & 0xFFu);
    block[63] = uint8_t( bit_len        & 0xFFu);
    sha256_block(h, block);

    // Output big-endian.
    #pragma unroll
    for (uint32_t i = 0; i < 8u; ++i) {
        out[i * 4 + 0] = uint8_t((h[i] >> 24) & 0xFFu);
        out[i * 4 + 1] = uint8_t((h[i] >> 16) & 0xFFu);
        out[i * 4 + 2] = uint8_t((h[i] >>  8) & 0xFFu);
        out[i * 4 + 3] = uint8_t( h[i]        & 0xFFu);
    }
}

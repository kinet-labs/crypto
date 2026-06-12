// BLAKE2b-512 batch hashing — CUDA implementation (RFC 7693).
// Byte-equal to blake2b/c-abi/blake2b_full.cpp::hash() and to
// blake2b/gpu/metal/blake2b_batch.metal::blake2b_jobs.
//
// Algorithm: 12 rounds, 128-byte blocks, 64-byte digest. Counter `t`
// increments by the actual amount consumed (RFC 7693 sec 3.3). Final block
// flag inverts v[14]. SIGMA permutation cycles every 10 rounds (so rounds
// 10 and 11 reuse SIGMA[0] and SIGMA[1]).
//
// One thread per input. Layout matches the Metal/SHA-256/RIPEMD-160 drivers:
// caller fills a flat byte arena and per-input (offset, length) descriptors;
// outputs are 64-byte stride.
//
// When CRYPTO_ENABLE_CUDA=ON this file is fed to nvcc and exposes
// `blake2b_jobs` as a real __global__ kernel. When CUDA is off (default) the
// same file compiles as host C++ via the `__CUDA_ARCH__` shim and exposes
// `blake2b_batch_cuda_host` so the determinism test still runs 100/100 on
// non-CUDA hosts. The kernel body is shared — byte-equal by construction.

#include <cstdint>

#ifndef __CUDA_ARCH__
#define __device__
#define __global__
#define __shared__
struct dim3 { unsigned x, y, z; };
static dim3 blockIdx, blockDim, threadIdx;
#endif

// =============================================================================
// IV (RFC 7693 sec 2.6 — same as SHA-512 IV).
// =============================================================================
__device__ static const uint64_t IV[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL,
};

// =============================================================================
// SIGMA permutation (RFC 7693 sec 2.7). Round i uses SIGMA[i % 10].
// =============================================================================
__device__ static const uint8_t SIGMA[10][16] = {
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

// =============================================================================
// Mixing function G (RFC 7693 sec 3.1).
// =============================================================================
__device__ static inline uint64_t rotr64(uint64_t x, unsigned n) {
    return (x >> n) | (x << (64u - n));
}

__device__ static void g_mix(uint64_t v[16],
                             unsigned a, unsigned b, unsigned c, unsigned d,
                             uint64_t x, uint64_t y) {
    v[a] = v[a] + v[b] + x;
    v[d] = rotr64(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];
    v[b] = rotr64(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y;
    v[d] = rotr64(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = rotr64(v[b] ^ v[c], 63);
}

// =============================================================================
// Compression function F (RFC 7693 sec 3.2). 12 rounds.
// =============================================================================
__device__ static void blake2b_compress(uint64_t h[8], const uint64_t m[16],
                                        uint64_t t0, uint64_t t1, bool last) {
    uint64_t v[16];
    for (int i = 0; i < 8; ++i) v[i]     = h[i];
    for (int i = 0; i < 8; ++i) v[i + 8] = IV[i];
    v[12] ^= t0;
    v[13] ^= t1;
    if (last) v[14] = ~v[14];

    for (int r = 0; r < 12; ++r) {
        const uint8_t* s = SIGMA[r % 10];
        g_mix(v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
        g_mix(v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
        g_mix(v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
        g_mix(v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);
        g_mix(v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
        g_mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g_mix(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        g_mix(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[i + 8];
}

// =============================================================================
// Kernel — one thread per input. 64-byte (= 8 × u64) digest per output slot.
// =============================================================================
extern "C" __global__ void blake2b_jobs(
    const uint8_t*  __restrict__ inputs,
    const uint32_t* __restrict__ input_offsets,
    const uint32_t* __restrict__ input_lens,
    uint8_t*        __restrict__ outputs,
    uint32_t                     num_jobs)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= num_jobs) return;

    const uint8_t* in = inputs + input_offsets[tid];
    uint8_t* out = outputs + tid * 64u;
    uint32_t len = input_lens[tid];

    // Param block (RFC 7693 sec 2.5): digest_len=64, key_len=0, fanout=1,
    // depth=1. h[0] ^= 0x01010040.
    uint64_t h[8];
    for (int i = 0; i < 8; ++i) h[i] = IV[i];
    h[0] ^= 0x0000000001010040ULL;

    uint64_t t0 = 0, t1 = 0;
    uint64_t m[16];
    uint8_t  block[128];
    uint32_t pos = 0;

    // Stream all but the final block as non-last.
    while ((len - pos) > 128u) {
        for (int i = 0; i < 128; ++i) block[i] = in[pos + i];
        for (int i = 0; i < 16; ++i) {
            uint64_t w = 0;
            for (int b = 0; b < 8; ++b)
                w |= (uint64_t)block[i * 8 + b] << (b * 8);
            m[i] = w;
        }
        pos += 128u;
        uint64_t t0_new = t0 + 128u;
        if (t0_new < t0) ++t1;
        t0 = t0_new;
        blake2b_compress(h, m, t0, t1, false);
    }

    // Final (possibly partial) block, zero-padded.
    uint32_t rem = len - pos;
    for (int i = 0; i < 128; ++i) block[i] = 0;
    for (uint32_t i = 0; i < rem; ++i) block[i] = in[pos + i];
    for (int i = 0; i < 16; ++i) {
        uint64_t w = 0;
        for (int b = 0; b < 8; ++b)
            w |= (uint64_t)block[i * 8 + b] << (b * 8);
        m[i] = w;
    }
    uint64_t t0_new = t0 + (uint64_t)rem;
    if (t0_new < t0) ++t1;
    t0 = t0_new;
    blake2b_compress(h, m, t0, t1, true);

    // Little-endian state -> output digest.
    for (int i = 0; i < 8; ++i) {
        for (int b = 0; b < 8; ++b) {
            out[i * 8 + b] = (uint8_t)((h[i] >> (b * 8)) & 0xFFULL);
        }
    }
}

// =============================================================================
// Host-emulation entry. When this TU is compiled as plain C++ (CUDA disabled
// or unavailable on the build host) we replay the kernel sequentially per
// thread index. Same code, no GPU. Used by the determinism test to prove
// byte-equality with the CPU oracle on every host.
// =============================================================================
#ifndef __CUDA_ARCH__
extern "C" int blake2b_batch_cuda_host(
    const uint8_t*  data,
    const uint32_t* offsets,
    const uint32_t* lengths,
    uint8_t*        outputs,
    uint32_t        num_inputs)
{
    if (num_inputs == 0) return 0;
    if (!data || !offsets || !lengths || !outputs) return -1;

    for (uint32_t tid = 0; tid < num_inputs; ++tid) {
        blockIdx.x = tid;
        blockDim.x = 1;
        threadIdx.x = 0;
        blake2b_jobs(data, offsets, lengths, outputs, num_inputs);
    }
    return 0;
}
#endif

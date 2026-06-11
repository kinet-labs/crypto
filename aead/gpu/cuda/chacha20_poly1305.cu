// Batched ChaCha20-Poly1305 (RFC 8439). One thread per (key, nonce, aad,
// plaintext) message; output is byte-equal to kinet::crypto::aead::
// chacha20_poly1305::encrypt() in cpp/aead.cpp.
//
// Per-message fanout: typical AEAD workload of many TLS-record-sized
// messages. Per-block fanout is a future kernel. Layout matches
// gpu/metal/aead_batch.metal exactly.

#include <cstdint>

#ifndef __CUDA_ARCH__
#define __device__
#define __global__
#define __host__
struct dim3 { unsigned x, y, z; };
static dim3 blockIdx, blockDim, threadIdx;
#endif

extern "C" {

struct AeadJob {
    uint32_t aad_offset;
    uint32_t aad_len;
    uint32_t pt_offset;
    uint32_t pt_len;
    uint32_t ct_offset;
    uint32_t tag_offset;
    uint32_t key_offset;
    uint32_t nonce_offset;
};

}  // extern "C"

// ---------------------------------------------------------------------------
// ChaCha20 (RFC 8439 §2.3) -- direct port of metal/aead_batch.metal.
// ---------------------------------------------------------------------------

__device__ static inline uint32_t rotl32_d(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32u - n));
}

__device__ static inline void quarter(uint32_t& a, uint32_t& b,
                                      uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl32_d(d, 16u);
    c += d; b ^= c; b = rotl32_d(b, 12u);
    a += b; d ^= a; d = rotl32_d(d,  8u);
    c += d; b ^= c; b = rotl32_d(b,  7u);
}

__device__ static inline uint32_t load32_le_g(const uint8_t* p) {
    return  (uint32_t)p[0]
         | ((uint32_t)p[1] <<  8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

__device__ static inline void store32_le_t(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v      );
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

__device__ static inline void chacha20_block(const uint8_t* key,
                                             const uint8_t* nonce,
                                             uint32_t counter,
                                             uint8_t* out64) {
    uint32_t s[16];
    s[ 0] = 0x61707865u; s[ 1] = 0x3320646eu;
    s[ 2] = 0x79622d32u; s[ 3] = 0x6b206574u;
    s[ 4] = load32_le_g(key + 0);  s[ 5] = load32_le_g(key + 4);
    s[ 6] = load32_le_g(key + 8);  s[ 7] = load32_le_g(key + 12);
    s[ 8] = load32_le_g(key + 16); s[ 9] = load32_le_g(key + 20);
    s[10] = load32_le_g(key + 24); s[11] = load32_le_g(key + 28);
    s[12] = counter;
    s[13] = load32_le_g(nonce + 0);
    s[14] = load32_le_g(nonce + 4);
    s[15] = load32_le_g(nonce + 8);

    uint32_t v[16];
    for (uint32_t i = 0; i < 16; ++i) v[i] = s[i];
    for (uint32_t i = 0; i < 10; ++i) {
        quarter(v[0], v[4], v[ 8], v[12]);
        quarter(v[1], v[5], v[ 9], v[13]);
        quarter(v[2], v[6], v[10], v[14]);
        quarter(v[3], v[7], v[11], v[15]);
        quarter(v[0], v[5], v[10], v[15]);
        quarter(v[1], v[6], v[11], v[12]);
        quarter(v[2], v[7], v[ 8], v[13]);
        quarter(v[3], v[4], v[ 9], v[14]);
    }
    for (uint32_t i = 0; i < 16; ++i) {
        store32_le_t(out64 + i * 4, v[i] + s[i]);
    }
}

// ---------------------------------------------------------------------------
// Poly1305 (RFC 8439 §2.5, radix 2^26).
// ---------------------------------------------------------------------------

struct Poly {
    uint32_t r[5];
    uint32_t s[4];
    uint32_t h[5];
};

__device__ static inline uint32_t load32_le_t(const uint8_t* p) {
    return  (uint32_t)p[0]
         | ((uint32_t)p[1] <<  8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

__device__ static inline void poly_init(Poly& st, const uint8_t* key) {
    uint32_t c0 = load32_le_t(key + 0)  & 0x0fffffffu;
    uint32_t c1 = load32_le_t(key + 4)  & 0x0ffffffcu;
    uint32_t c2 = load32_le_t(key + 8)  & 0x0ffffffcu;
    uint32_t c3 = load32_le_t(key + 12) & 0x0ffffffcu;
    st.r[0] =  c0                       & 0x3ffffffu;
    st.r[1] = ((c0 >> 26) | (c1 <<  6)) & 0x3ffffffu;
    st.r[2] = ((c1 >> 20) | (c2 << 12)) & 0x3ffffffu;
    st.r[3] = ((c2 >> 14) | (c3 << 18)) & 0x3ffffffu;
    st.r[4] =  (c3 >> 8)                & 0x3ffffffu;

    st.s[0] = load32_le_t(key + 16);
    st.s[1] = load32_le_t(key + 20);
    st.s[2] = load32_le_t(key + 24);
    st.s[3] = load32_le_t(key + 28);
    for (uint32_t i = 0; i < 5; ++i) st.h[i] = 0u;
}

__device__ static inline void poly_block(Poly& st, const uint8_t* m,
                                          uint32_t hibit) {
    uint32_t t0 = load32_le_t(m + 0);
    uint32_t t1 = load32_le_t(m + 4);
    uint32_t t2 = load32_le_t(m + 8);
    uint32_t t3 = load32_le_t(m + 12);

    uint64_t h0 = (uint64_t)st.h[0] + ( t0                       & 0x3ffffffu);
    uint64_t h1 = (uint64_t)st.h[1] + (((t0 >> 26) | (t1 <<  6)) & 0x3ffffffu);
    uint64_t h2 = (uint64_t)st.h[2] + (((t1 >> 20) | (t2 << 12)) & 0x3ffffffu);
    uint64_t h3 = (uint64_t)st.h[3] + (((t2 >> 14) | (t3 << 18)) & 0x3ffffffu);
    uint64_t h4 = (uint64_t)st.h[4] + ( (t3 >>  8)               | (uint64_t)hibit);

    uint64_t r0 = st.r[0]; uint64_t r1 = st.r[1];
    uint64_t r2 = st.r[2]; uint64_t r3 = st.r[3];
    uint64_t r4 = st.r[4];
    uint64_t s1 = r1 * 5UL; uint64_t s2 = r2 * 5UL;
    uint64_t s3 = r3 * 5UL; uint64_t s4 = r4 * 5UL;

    uint64_t d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
    uint64_t d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2;
    uint64_t d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3;
    uint64_t d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4;
    uint64_t d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;

    uint64_t c;
    c = d0 >> 26; d0 &= 0x3ffffffUL; d1 += c;
    c = d1 >> 26; d1 &= 0x3ffffffUL; d2 += c;
    c = d2 >> 26; d2 &= 0x3ffffffUL; d3 += c;
    c = d3 >> 26; d3 &= 0x3ffffffUL; d4 += c;
    c = d4 >> 26; d4 &= 0x3ffffffUL; d0 += c * 5UL;
    c = d0 >> 26; d0 &= 0x3ffffffUL; d1 += c;

    st.h[0] = (uint32_t)d0;
    st.h[1] = (uint32_t)d1;
    st.h[2] = (uint32_t)d2;
    st.h[3] = (uint32_t)d3;
    st.h[4] = (uint32_t)d4;
}

__device__ static inline void poly_finalize(Poly& st, uint8_t* tag) {
    uint32_t h0 = st.h[0], h1 = st.h[1], h2 = st.h[2], h3 = st.h[3], h4 = st.h[4];
    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffffu; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffffu; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffffu; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffffu; h0 += c * 5u;
    c = h0 >> 26; h0 &= 0x3ffffffu; h1 += c;

    uint32_t g0 = h0 + 5u; c = g0 >> 26; g0 &= 0x3ffffffu;
    uint32_t g1 = h1 + c;  c = g1 >> 26; g1 &= 0x3ffffffu;
    uint32_t g2 = h2 + c;  c = g2 >> 26; g2 &= 0x3ffffffu;
    uint32_t g3 = h3 + c;  c = g3 >> 26; g3 &= 0x3ffffffu;
    uint32_t g4 = h4 + c - (1u << 26);

    uint32_t mask = (g4 >> 31) - 1u;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    uint32_t nm = ~mask;
    h0 = (h0 & nm) | g0;
    h1 = (h1 & nm) | g1;
    h2 = (h2 & nm) | g2;
    h3 = (h3 & nm) | g3;
    h4 = (h4 & nm) | g4;

    uint32_t f0 =  h0        | (h1 << 26);
    uint32_t f1 = (h1 >>  6) | (h2 << 20);
    uint32_t f2 = (h2 >> 12) | (h3 << 14);
    uint32_t f3 = (h3 >> 18) | (h4 <<  8);

    uint64_t t = (uint64_t)f0 + (uint64_t)st.s[0];
    store32_le_t(tag + 0, (uint32_t)t);
    t = (t >> 32) + (uint64_t)f1 + (uint64_t)st.s[1];
    store32_le_t(tag + 4, (uint32_t)t);
    t = (t >> 32) + (uint64_t)f2 + (uint64_t)st.s[2];
    store32_le_t(tag + 8, (uint32_t)t);
    t = (t >> 32) + (uint64_t)f3 + (uint64_t)st.s[3];
    store32_le_t(tag + 12, (uint32_t)t);
}

// Absorb a buffer with RFC 8439 AEAD framing: full 16-byte blocks, final
// partial block zero-padded to 16 bytes (NO 0x01 marker; the AEAD
// construction handles framing).
__device__ static inline void absorb_padded(Poly& st,
                                             const uint8_t* arena,
                                             uint32_t off, uint32_t len) {
    uint32_t pos = 0;
    while (len - pos >= 16u) {
        uint8_t buf[16];
        for (uint32_t i = 0; i < 16; ++i) buf[i] = arena[off + pos + i];
        poly_block(st, buf, 1u << 24);
        pos += 16u;
    }
    uint32_t rem = len - pos;
    if (rem > 0u) {
        uint8_t buf[16];
        for (uint32_t i = 0; i < 16; ++i) buf[i] = 0;
        for (uint32_t i = 0; i < rem; ++i) buf[i] = arena[off + pos + i];
        poly_block(st, buf, 1u << 24);
    }
}

// ---------------------------------------------------------------------------
// Kernel: one thread per ChaCha20-Poly1305 AEAD job.
// ---------------------------------------------------------------------------

extern "C" __global__ void chacha20_poly1305_jobs(
    const AeadJob* __restrict__ jobs,
    const uint8_t* __restrict__ keys,
    const uint8_t* __restrict__ nonces,
    const uint8_t* __restrict__ inputs_arena,
    uint8_t*       __restrict__ outputs_arena,
    uint32_t                    n_jobs)
{
    uint32_t gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= n_jobs) return;

    AeadJob job = jobs[gid];
    const uint8_t* key   = keys   + job.key_offset;
    const uint8_t* nonce = nonces + job.nonce_offset;

    // Derive Poly1305 one-time key from ChaCha20 block 0.
    uint8_t poly_key[32];
    {
        uint8_t ks[64];
        chacha20_block(key, nonce, 0u, ks);
        for (uint32_t i = 0; i < 32u; ++i) poly_key[i] = ks[i];
    }

    // Encrypt plaintext with counter starting at 1.
    {
        uint8_t ks[64];
        uint32_t counter = 1u;
        uint32_t pos = 0u;
        while (pos < job.pt_len) {
            chacha20_block(key, nonce, counter, ks);
            uint32_t take = job.pt_len - pos;
            if (take > 64u) take = 64u;
            for (uint32_t i = 0; i < take; ++i) {
                outputs_arena[job.ct_offset + pos + i] =
                    inputs_arena[job.pt_offset + pos + i] ^ ks[i];
            }
            pos += take;
            ++counter;
        }
    }

    // MAC over (aad || pad || ct || pad || lens).
    Poly st;
    poly_init(st, poly_key);
    absorb_padded(st, inputs_arena, job.aad_offset, job.aad_len);
    absorb_padded(st, outputs_arena, job.ct_offset, job.pt_len);
    {
        uint8_t lens[16];
        uint64_t la = (uint64_t)job.aad_len;
        uint64_t lc = (uint64_t)job.pt_len;
        for (uint32_t i = 0; i < 8u; ++i) lens[i]      = (uint8_t)(la >> (8u * i));
        for (uint32_t i = 0; i < 8u; ++i) lens[8u + i] = (uint8_t)(lc >> (8u * i));
        poly_block(st, lens, 1u << 24);
    }
    uint8_t tag[16];
    poly_finalize(st, tag);
    for (uint32_t i = 0; i < 16u; ++i) {
        outputs_arena[job.tag_offset + i] = tag[i];
    }
}

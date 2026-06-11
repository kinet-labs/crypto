// Batched ChaCha20-Poly1305 (RFC 8439). One thread per (key, nonce, aad,
// plaintext) message; output is byte-equal to kinet::crypto::aead::
// chacha20_poly1305::encrypt() in cpp/aead.cpp.
//
// Per-message fanout: useful for the typical AEAD workload of many
// TLS-record-sized messages. For very large per-message payloads we'd want
// per-block fanout instead; that's a future kernel.
//
// Layout:
//   * keys[i*32..]       -- 32-byte ChaCha20 key for message i
//   * nonces[i*12..]     -- 12-byte nonce for message i
//   * inputs_arena[..]   -- packed concatenation of (aad || plaintext) per
//                           message; offsets/lens given by the per-message
//                           job table.
//   * outputs_arena[..]  -- packed concatenation of (ciphertext || tag(16))
//                           per message.

#include <metal_stdlib>
using namespace metal;

struct AeadJob {
    uint32_t aad_offset;     // byte offset into inputs_arena
    uint32_t aad_len;
    uint32_t pt_offset;      // byte offset into inputs_arena
    uint32_t pt_len;
    uint32_t ct_offset;      // byte offset into outputs_arena (ciphertext)
    uint32_t tag_offset;     // byte offset into outputs_arena (16 byte tag)
    uint32_t key_offset;     // byte offset into keys[] (always i*32)
    uint32_t nonce_offset;   // byte offset into nonces[] (always i*12)
};

// ---------------------------------------------------------------------------
// ChaCha20
// ---------------------------------------------------------------------------

inline uint rotl32_d(uint x, uint n) { return (x << n) | (x >> (32u - n)); }

inline void quarter(thread uint& a, thread uint& b, thread uint& c, thread uint& d) {
    a += b; d ^= a; d = rotl32_d(d, 16u);
    c += d; b ^= c; b = rotl32_d(b, 12u);
    a += b; d ^= a; d = rotl32_d(d,  8u);
    c += d; b ^= c; b = rotl32_d(b,  7u);
}

inline uint load32_le_d(const device uint8_t* p) {
    return  (uint)p[0]
         | ((uint)p[1] <<  8)
         | ((uint)p[2] << 16)
         | ((uint)p[3] << 24);
}

inline void store32_le_t(thread uint8_t* p, uint v) {
    p[0] = (uint8_t)(v      );
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

inline void chacha20_block(const device uint8_t* key,
                           const device uint8_t* nonce,
                           uint counter,
                           thread uint8_t* out64) {
    uint s[16];
    s[ 0] = 0x61707865u; s[ 1] = 0x3320646eu;
    s[ 2] = 0x79622d32u; s[ 3] = 0x6b206574u;
    s[ 4] = load32_le_d(key + 0);  s[ 5] = load32_le_d(key + 4);
    s[ 6] = load32_le_d(key + 8);  s[ 7] = load32_le_d(key + 12);
    s[ 8] = load32_le_d(key + 16); s[ 9] = load32_le_d(key + 20);
    s[10] = load32_le_d(key + 24); s[11] = load32_le_d(key + 28);
    s[12] = counter;
    s[13] = load32_le_d(nonce + 0);
    s[14] = load32_le_d(nonce + 4);
    s[15] = load32_le_d(nonce + 8);

    uint v[16];
    for (uint i = 0; i < 16; ++i) v[i] = s[i];
    for (uint i = 0; i < 10; ++i) {
        quarter(v[0], v[4], v[ 8], v[12]);
        quarter(v[1], v[5], v[ 9], v[13]);
        quarter(v[2], v[6], v[10], v[14]);
        quarter(v[3], v[7], v[11], v[15]);
        quarter(v[0], v[5], v[10], v[15]);
        quarter(v[1], v[6], v[11], v[12]);
        quarter(v[2], v[7], v[ 8], v[13]);
        quarter(v[3], v[4], v[ 9], v[14]);
    }
    for (uint i = 0; i < 16; ++i) {
        store32_le_t(out64 + i * 4, v[i] + s[i]);
    }
}

// ---------------------------------------------------------------------------
// Poly1305 (radix 2^26)
// ---------------------------------------------------------------------------
//
// State held entirely in thread-private storage; we operate on full 16-byte
// blocks (caller is responsible for zero-padding partial tails as required
// by RFC 8439 §2.8 for the AEAD construction).

struct Poly {
    uint r[5];
    uint s[4];
    uint h[5];
};

inline uint load32_le_t(thread const uint8_t* p) {
    return  (uint)p[0]
         | ((uint)p[1] <<  8)
         | ((uint)p[2] << 16)
         | ((uint)p[3] << 24);
}

inline void poly_init(thread Poly& st, thread const uint8_t* key) {
    uint c0 = load32_le_t(key + 0)  & 0x0fffffffu;
    uint c1 = load32_le_t(key + 4)  & 0x0ffffffcu;
    uint c2 = load32_le_t(key + 8)  & 0x0ffffffcu;
    uint c3 = load32_le_t(key + 12) & 0x0ffffffcu;
    st.r[0] =  c0                       & 0x3ffffffu;
    st.r[1] = ((c0 >> 26) | (c1 <<  6)) & 0x3ffffffu;
    st.r[2] = ((c1 >> 20) | (c2 << 12)) & 0x3ffffffu;
    st.r[3] = ((c2 >> 14) | (c3 << 18)) & 0x3ffffffu;
    st.r[4] =  (c3 >> 8)                & 0x3ffffffu;

    st.s[0] = load32_le_t(key + 16);
    st.s[1] = load32_le_t(key + 20);
    st.s[2] = load32_le_t(key + 24);
    st.s[3] = load32_le_t(key + 28);
    for (uint i = 0; i < 5; ++i) st.h[i] = 0u;
}

inline void poly_block(thread Poly& st, thread const uint8_t* m, uint hibit) {
    uint t0 = load32_le_t(m + 0);
    uint t1 = load32_le_t(m + 4);
    uint t2 = load32_le_t(m + 8);
    uint t3 = load32_le_t(m + 12);

    ulong h0 = (ulong)st.h[0] + ( t0                       & 0x3ffffffu);
    ulong h1 = (ulong)st.h[1] + (((t0 >> 26) | (t1 <<  6)) & 0x3ffffffu);
    ulong h2 = (ulong)st.h[2] + (((t1 >> 20) | (t2 << 12)) & 0x3ffffffu);
    ulong h3 = (ulong)st.h[3] + (((t2 >> 14) | (t3 << 18)) & 0x3ffffffu);
    ulong h4 = (ulong)st.h[4] + ( (t3 >>  8)               | (ulong)hibit);

    ulong r0 = st.r[0]; ulong r1 = st.r[1];
    ulong r2 = st.r[2]; ulong r3 = st.r[3];
    ulong r4 = st.r[4];
    ulong s1 = r1 * 5UL; ulong s2 = r2 * 5UL;
    ulong s3 = r3 * 5UL; ulong s4 = r4 * 5UL;

    ulong d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
    ulong d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2;
    ulong d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3;
    ulong d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4;
    ulong d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;

    ulong c;
    c = d0 >> 26; d0 &= 0x3ffffffUL; d1 += c;
    c = d1 >> 26; d1 &= 0x3ffffffUL; d2 += c;
    c = d2 >> 26; d2 &= 0x3ffffffUL; d3 += c;
    c = d3 >> 26; d3 &= 0x3ffffffUL; d4 += c;
    c = d4 >> 26; d4 &= 0x3ffffffUL; d0 += c * 5UL;
    c = d0 >> 26; d0 &= 0x3ffffffUL; d1 += c;

    st.h[0] = (uint)d0;
    st.h[1] = (uint)d1;
    st.h[2] = (uint)d2;
    st.h[3] = (uint)d3;
    st.h[4] = (uint)d4;
}

inline void poly_finalize(thread Poly& st, thread uint8_t* tag) {
    uint h0 = st.h[0], h1 = st.h[1], h2 = st.h[2], h3 = st.h[3], h4 = st.h[4];
    uint c;
    c = h1 >> 26; h1 &= 0x3ffffffu; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffffu; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffffu; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffffu; h0 += c * 5u;
    c = h0 >> 26; h0 &= 0x3ffffffu; h1 += c;

    uint g0 = h0 + 5u; c = g0 >> 26; g0 &= 0x3ffffffu;
    uint g1 = h1 + c;  c = g1 >> 26; g1 &= 0x3ffffffu;
    uint g2 = h2 + c;  c = g2 >> 26; g2 &= 0x3ffffffu;
    uint g3 = h3 + c;  c = g3 >> 26; g3 &= 0x3ffffffu;
    uint g4 = h4 + c - (1u << 26);

    uint mask = (g4 >> 31) - 1u;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    uint nm = ~mask;
    h0 = (h0 & nm) | g0;
    h1 = (h1 & nm) | g1;
    h2 = (h2 & nm) | g2;
    h3 = (h3 & nm) | g3;
    h4 = (h4 & nm) | g4;

    uint f0 =  h0        | (h1 << 26);
    uint f1 = (h1 >>  6) | (h2 << 20);
    uint f2 = (h2 >> 12) | (h3 << 14);
    uint f3 = (h3 >> 18) | (h4 <<  8);

    ulong t = (ulong)f0 + (ulong)st.s[0];
    store32_le_t(tag + 0, (uint)t);
    t = (t >> 32) + (ulong)f1 + (ulong)st.s[1];
    store32_le_t(tag + 4, (uint)t);
    t = (t >> 32) + (ulong)f2 + (ulong)st.s[2];
    store32_le_t(tag + 8, (uint)t);
    t = (t >> 32) + (ulong)f3 + (ulong)st.s[3];
    store32_le_t(tag + 12, (uint)t);
}

// Absorb a buffer with RFC 8439 AEAD framing: full 16-byte blocks, final
// partial block zero-padded to 16 bytes (NO 0x01 marker).
inline void absorb_padded(thread Poly& st,
                          const device uint8_t* arena,
                          uint off, uint len) {
    uint pos = 0;
    while (len - pos >= 16) {
        // Copy 16 bytes from device memory to thread memory.
        thread uint8_t buf[16];
        for (uint i = 0; i < 16; ++i) buf[i] = arena[off + pos + i];
        poly_block(st, buf, 1u << 24);
        pos += 16;
    }
    uint rem = len - pos;
    if (rem > 0) {
        thread uint8_t buf[16];
        for (uint i = 0; i < 16; ++i) buf[i] = 0;
        for (uint i = 0; i < rem; ++i) buf[i] = arena[off + pos + i];
        poly_block(st, buf, 1u << 24);
    }
}

// ---------------------------------------------------------------------------
// Kernel: one thread per AEAD job.
// ---------------------------------------------------------------------------

kernel void aead_jobs(
    device const AeadJob*  jobs           [[buffer(0)]],
    device const uint8_t*  keys           [[buffer(1)]],
    device const uint8_t*  nonces         [[buffer(2)]],
    device const uint8_t*  inputs_arena   [[buffer(3)]],
    device       uint8_t*  outputs_arena  [[buffer(4)]],
    device const uint&     n_jobs         [[buffer(5)]],
    uint                   gid            [[thread_position_in_grid]])
{
    if (gid >= n_jobs) return;

    AeadJob job = jobs[gid];
    const device uint8_t* key   = keys   + job.key_offset;
    const device uint8_t* nonce = nonces + job.nonce_offset;

    // ---- Derive Poly1305 one-time key from ChaCha20 block 0 ---------------
    thread uint8_t poly_key[32];
    {
        thread uint8_t ks[64];
        chacha20_block(key, nonce, 0u, ks);
        for (uint i = 0; i < 32; ++i) poly_key[i] = ks[i];
    }

    // ---- Encrypt plaintext with counter starting at 1 ---------------------
    {
        thread uint8_t ks[64];
        uint counter = 1u;
        uint pos = 0;
        while (pos < job.pt_len) {
            chacha20_block(key, nonce, counter, ks);
            uint take = job.pt_len - pos;
            if (take > 64) take = 64;
            for (uint i = 0; i < take; ++i) {
                outputs_arena[job.ct_offset + pos + i] =
                    inputs_arena[job.pt_offset + pos + i] ^ ks[i];
            }
            pos += take;
            ++counter;
        }
    }

    // ---- Compute MAC over (aad || pad || ct || pad || lens) ---------------
    Poly st;
    poly_init(st, poly_key);
    absorb_padded(st, inputs_arena, job.aad_offset, job.aad_len);
    absorb_padded(st, outputs_arena, job.ct_offset, job.pt_len);
    {
        thread uint8_t lens[16];
        ulong la = (ulong)job.aad_len;
        ulong lc = (ulong)job.pt_len;
        for (uint i = 0; i < 8; ++i) lens[i]     = (uint8_t)(la >> (8u * i));
        for (uint i = 0; i < 8; ++i) lens[8 + i] = (uint8_t)(lc >> (8u * i));
        poly_block(st, lens, 1u << 24);
    }
    thread uint8_t tag[16];
    poly_finalize(st, tag);
    for (uint i = 0; i < 16; ++i) {
        outputs_arena[job.tag_offset + i] = tag[i];
    }
}

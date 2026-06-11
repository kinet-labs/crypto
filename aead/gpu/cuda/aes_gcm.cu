// Batched AES-256-GCM (NIST SP 800-38D, 96-bit IV). One thread per
// (key, iv, aad, plaintext) message; output is byte-equal to
// kinet::crypto::aead::aes_256_gcm::encrypt() in cpp/aead.cpp.
//
// Per-message fanout. Constant-time S-box (Boyar-Peralta) -- table-free,
// no data-dependent branches. Constant-time GHASH (128 iterations always).

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

// AES-256: 14 rounds, expanded round-key schedule = 240 bytes (15 round keys).
#define AES256_ROUNDS    14u
#define AES256_KS_BYTES 240u

// ---------------------------------------------------------------------------
// AES S-box -- Boyar-Peralta circuit (J. Cryptol. 2010). Byte-for-byte port
// of kinet::crypto::aead::aes::aes_sbox in cpp/aead.cpp.
// ---------------------------------------------------------------------------
__device__ static inline uint8_t aes_sbox(uint8_t x) {
    uint8_t U0 = (x >> 7) & 1u;
    uint8_t U1 = (x >> 6) & 1u;
    uint8_t U2 = (x >> 5) & 1u;
    uint8_t U3 = (x >> 4) & 1u;
    uint8_t U4 = (x >> 3) & 1u;
    uint8_t U5 = (x >> 2) & 1u;
    uint8_t U6 = (x >> 1) & 1u;
    uint8_t U7 =  x       & 1u;

    uint8_t T1  = U0 ^ U3;
    uint8_t T2  = U0 ^ U5;
    uint8_t T3  = U0 ^ U6;
    uint8_t T4  = U3 ^ U5;
    uint8_t T5  = U4 ^ U6;
    uint8_t T6  = T1 ^ T5;
    uint8_t T7  = U1 ^ U2;
    uint8_t T8  = U7 ^ T6;
    uint8_t T9  = U7 ^ T7;
    uint8_t T10 = T6 ^ T7;
    uint8_t T11 = U1 ^ U5;
    uint8_t T12 = U2 ^ U5;
    uint8_t T13 = T3 ^ T4;
    uint8_t T14 = T6 ^ T11;
    uint8_t T15 = T5 ^ T11;
    uint8_t T16 = T5 ^ T12;
    uint8_t T17 = T9 ^ T16;
    uint8_t T18 = U3 ^ U7;
    uint8_t T19 = T7 ^ T18;
    uint8_t T20 = T1 ^ T19;
    uint8_t T21 = U6 ^ U7;
    uint8_t T22 = T7 ^ T21;
    uint8_t T23 = T2 ^ T22;
    uint8_t T24 = T2 ^ T10;
    uint8_t T25 = T20 ^ T17;
    uint8_t T26 = T3 ^ T16;
    uint8_t T27 = T1 ^ T12;

    uint8_t M1  = T13 & T6;
    uint8_t M2  = T23 & T8;
    uint8_t M3  = T14 ^ M1;
    uint8_t M4  = T19 & U7;
    uint8_t M5  = M4 ^ M1;
    uint8_t M6  = T3 & T16;
    uint8_t M7  = T22 & T9;
    uint8_t M8  = T26 ^ M6;
    uint8_t M9  = T20 & T17;
    uint8_t M10 = M9 ^ M6;
    uint8_t M11 = T1 & T15;
    uint8_t M12 = T4 & T27;
    uint8_t M13 = M12 ^ M11;
    uint8_t M14 = T2 & T10;
    uint8_t M15 = M14 ^ M11;
    uint8_t M16 = M3 ^ M2;
    uint8_t M17 = M5 ^ T24;
    uint8_t M18 = M8 ^ M7;
    uint8_t M19 = M10 ^ M15;
    uint8_t M20 = M16 ^ M13;
    uint8_t M21 = M17 ^ M15;
    uint8_t M22 = M18 ^ M13;
    uint8_t M23 = M19 ^ T25;
    uint8_t M24 = M22 ^ M23;
    uint8_t M25 = M22 & M20;
    uint8_t M26 = M21 ^ M25;
    uint8_t M27 = M20 ^ M21;
    uint8_t M28 = M23 ^ M25;
    uint8_t M29 = M28 & M27;
    uint8_t M30 = M26 & M24;
    uint8_t M31 = M20 & M23;
    uint8_t M32 = M27 & M31;
    uint8_t M33 = M27 ^ M25;
    uint8_t M34 = M21 & M22;
    uint8_t M35 = M24 & M34;
    uint8_t M36 = M24 ^ M25;
    uint8_t M37 = M21 ^ M29;
    uint8_t M38 = M32 ^ M33;
    uint8_t M39 = M23 ^ M30;
    uint8_t M40 = M35 ^ M36;
    uint8_t M41 = M38 ^ M40;
    uint8_t M42 = M37 ^ M39;
    uint8_t M43 = M37 ^ M38;
    uint8_t M44 = M39 ^ M40;
    uint8_t M45 = M42 ^ M41;
    uint8_t M46 = M44 & T6;
    uint8_t M47 = M40 & T8;
    uint8_t M48 = M39 & U7;
    uint8_t M49 = M43 & T16;
    uint8_t M50 = M38 & T9;
    uint8_t M51 = M37 & T17;
    uint8_t M52 = M42 & T15;
    uint8_t M53 = M45 & T27;
    uint8_t M54 = M41 & T10;
    uint8_t M55 = M44 & T13;
    uint8_t M56 = M40 & T23;
    uint8_t M57 = M39 & T19;
    uint8_t M58 = M43 & T3;
    uint8_t M59 = M38 & T22;
    uint8_t M60 = M37 & T20;
    uint8_t M61 = M42 & T1;
    uint8_t M62 = M45 & T4;
    uint8_t M63 = M41 & T2;

    uint8_t L0  = M61 ^ M62;
    uint8_t L1  = M50 ^ M56;
    uint8_t L2  = M46 ^ M48;
    uint8_t L3  = M47 ^ M55;
    uint8_t L4  = M54 ^ M58;
    uint8_t L5  = M49 ^ M61;
    uint8_t L6  = M62 ^ L5;
    uint8_t L7  = M46 ^ L3;
    uint8_t L8  = M51 ^ M59;
    uint8_t L9  = M52 ^ M53;
    uint8_t L10 = M53 ^ L4;
    uint8_t L11 = M60 ^ L2;
    uint8_t L12 = M48 ^ M51;
    uint8_t L13 = M50 ^ L0;
    uint8_t L14 = M52 ^ M61;
    uint8_t L15 = M55 ^ L1;
    uint8_t L16 = M56 ^ L0;
    uint8_t L17 = M57 ^ L1;
    uint8_t L18 = M58 ^ L8;
    uint8_t L19 = M63 ^ L4;
    uint8_t L20 = L0 ^ L1;
    uint8_t L21 = L1 ^ L7;
    uint8_t L22 = L3 ^ L12;
    uint8_t L23 = L18 ^ L2;
    uint8_t L24 = L15 ^ L9;
    uint8_t L25 = L6 ^ L10;
    uint8_t L26 = L7 ^ L9;
    uint8_t L27 = L8 ^ L10;
    uint8_t L28 = L11 ^ L14;
    uint8_t L29 = L11 ^ L17;

    uint8_t S0 = L6  ^ L24;
    uint8_t S1 = L16 ^ L26;     S1 ^= 1u;
    uint8_t S2 = L19 ^ L28;     S2 ^= 1u;
    uint8_t S3 = L6  ^ L21;
    uint8_t S4 = L20 ^ L22;
    uint8_t S5 = L25 ^ L29;
    uint8_t S6 = L13 ^ L27;     S6 ^= 1u;
    uint8_t S7 = L6  ^ L23;     S7 ^= 1u;

    return (uint8_t)(
        ((S0 & 1u) << 7) |
        ((S1 & 1u) << 6) |
        ((S2 & 1u) << 5) |
        ((S3 & 1u) << 4) |
        ((S4 & 1u) << 3) |
        ((S5 & 1u) << 2) |
        ((S6 & 1u) << 1) |
        ( S7 & 1u));
}

// FIPS 197 round-constants for AES-256 (only Rcon[0..6] needed).
__device__ static const uint8_t RCON[7] = {
    0x01u, 0x02u, 0x04u, 0x08u, 0x10u, 0x20u, 0x40u
};

__device__ static inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1u) * 0x1bu));
}

// ---------------------------------------------------------------------------
// AES-256 key expansion (FIPS 197 §5.2). Output: 240-byte round-key schedule.
// ---------------------------------------------------------------------------
__device__ static inline void aes256_expand_key(const uint8_t* key, uint8_t* rk) {
    for (uint32_t i = 0u; i < 32u; ++i) rk[i] = key[i];

    for (uint32_t i = 8u; i < 60u; ++i) {
        uint8_t t0 = rk[(i - 1u) * 4u + 0u];
        uint8_t t1 = rk[(i - 1u) * 4u + 1u];
        uint8_t t2 = rk[(i - 1u) * 4u + 2u];
        uint8_t t3 = rk[(i - 1u) * 4u + 3u];

        if ((i & 7u) == 0u) {
            uint8_t r0 = t1, r1 = t2, r2 = t3, r3 = t0;
            t0 = (uint8_t)(aes_sbox(r0) ^ RCON[(i / 8u) - 1u]);
            t1 = aes_sbox(r1);
            t2 = aes_sbox(r2);
            t3 = aes_sbox(r3);
        } else if ((i & 7u) == 4u) {
            t0 = aes_sbox(t0);
            t1 = aes_sbox(t1);
            t2 = aes_sbox(t2);
            t3 = aes_sbox(t3);
        }

        rk[i * 4u + 0u] = (uint8_t)(rk[(i - 8u) * 4u + 0u] ^ t0);
        rk[i * 4u + 1u] = (uint8_t)(rk[(i - 8u) * 4u + 1u] ^ t1);
        rk[i * 4u + 2u] = (uint8_t)(rk[(i - 8u) * 4u + 2u] ^ t2);
        rk[i * 4u + 3u] = (uint8_t)(rk[(i - 8u) * 4u + 3u] ^ t3);
    }
}

// ---------------------------------------------------------------------------
// AES-256 encrypt one 16-byte block (FIPS 197 §5.1). State layout column-
// major: s[c*4 + r]. Byte-for-byte equivalent to aes::encrypt_block in
// cpp/aead.cpp.
// ---------------------------------------------------------------------------
__device__ static inline void aes256_encrypt_block(const uint8_t* rk,
                                                    const uint8_t* in,
                                                    uint8_t* out) {
    uint8_t s[16];
    for (uint32_t i = 0u; i < 16u; ++i) s[i] = (uint8_t)(in[i] ^ rk[i]);

    for (uint32_t round = 1u; round < AES256_ROUNDS; ++round) {
        for (uint32_t i = 0u; i < 16u; ++i) s[i] = aes_sbox(s[i]);

        // ShiftRows (column-major: row r at indices r, r+4, r+8, r+12).
        uint8_t t;
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        t = s[2];  s[2]  = s[10]; s[10] = t;
        t = s[6];  s[6]  = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;

        // MixColumns.
        for (uint32_t c = 0u; c < 4u; ++c) {
            uint8_t a0 = s[c*4u + 0u];
            uint8_t a1 = s[c*4u + 1u];
            uint8_t a2 = s[c*4u + 2u];
            uint8_t a3 = s[c*4u + 3u];
            uint8_t x  = a0 ^ a1 ^ a2 ^ a3;
            uint8_t y0 = a0;
            s[c*4u + 0u] = (uint8_t)(a0 ^ x ^ xtime(a0 ^ a1));
            s[c*4u + 1u] = (uint8_t)(a1 ^ x ^ xtime(a1 ^ a2));
            s[c*4u + 2u] = (uint8_t)(a2 ^ x ^ xtime(a2 ^ a3));
            s[c*4u + 3u] = (uint8_t)(a3 ^ x ^ xtime(a3 ^ y0));
        }

        for (uint32_t i = 0u; i < 16u; ++i) s[i] ^= rk[round * 16u + i];
    }

    // Final round (no MixColumns).
    for (uint32_t i = 0u; i < 16u; ++i) s[i] = aes_sbox(s[i]);
    {
        uint8_t t;
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        t = s[2];  s[2]  = s[10]; s[10] = t;
        t = s[6];  s[6]  = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
    }
    for (uint32_t i = 0u; i < 16u; ++i) {
        out[i] = (uint8_t)(s[i] ^ rk[AES256_ROUNDS * 16u + i]);
    }
}

// ---------------------------------------------------------------------------
// GHASH multiplication in GF(2^128) with reduction polynomial
// x^128 + x^7 + x^2 + x + 1 (NIST SP 800-38D §6.3). Bits are GCM-style
// (bit 0 = MSB of byte 0). Constant-time: 128 iterations always.
// ---------------------------------------------------------------------------
__device__ static inline void ghash_mul(uint8_t* z, const uint8_t* h) {
    uint8_t v[16];
    for (uint32_t i = 0u; i < 16u; ++i) v[i] = h[i];
    uint8_t r[16];
    for (uint32_t i = 0u; i < 16u; ++i) r[i] = 0u;

    for (uint32_t i = 0u; i < 128u; ++i) {
        uint8_t zbit = (uint8_t)((z[i >> 3] >> (7u - (i & 7u))) & 1u);
        uint8_t mask = (uint8_t)(0u - (uint32_t)zbit);
        for (uint32_t j = 0u; j < 16u; ++j) r[j] ^= (uint8_t)(v[j] & mask);

        uint8_t lsb = (uint8_t)(v[15] & 1u);
        for (uint32_t j = 15u; j > 0u; --j) {
            v[j] = (uint8_t)((v[j] >> 1) | ((v[j-1u] & 1u) << 7));
        }
        v[0] >>= 1;
        uint8_t rmask = (uint8_t)(0u - (uint32_t)lsb);
        v[0] ^= (uint8_t)(0xe1u & rmask);
    }

    for (uint32_t i = 0u; i < 16u; ++i) z[i] = r[i];
}

__device__ static inline void inc32(uint8_t* ctr) {
    uint32_t c = ((uint32_t)ctr[12] << 24) | ((uint32_t)ctr[13] << 16)
               | ((uint32_t)ctr[14] <<  8) |  (uint32_t)ctr[15];
    c += 1u;
    ctr[12] = (uint8_t)(c >> 24);
    ctr[13] = (uint8_t)(c >> 16);
    ctr[14] = (uint8_t)(c >>  8);
    ctr[15] = (uint8_t)(c);
}

__device__ static inline void ghash_update(uint8_t* y, const uint8_t* h,
                                            const uint8_t* arena,
                                            uint32_t off, uint32_t len) {
    uint32_t pos = 0u;
    while (len - pos >= 16u) {
        for (uint32_t i = 0u; i < 16u; ++i) y[i] ^= arena[off + pos + i];
        ghash_mul(y, h);
        pos += 16u;
    }
    uint32_t rem = len - pos;
    if (rem > 0u) {
        uint8_t buf[16];
        for (uint32_t i = 0u; i < 16u; ++i) buf[i] = 0u;
        for (uint32_t i = 0u; i < rem; ++i) buf[i] = arena[off + pos + i];
        for (uint32_t i = 0u; i < 16u; ++i) y[i] ^= buf[i];
        ghash_mul(y, h);
    }
}

// ---------------------------------------------------------------------------
// Kernel: one thread per AEAD job. AES-256-GCM seal.
// ---------------------------------------------------------------------------
extern "C" __global__ void aes_gcm_jobs(
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
    const uint8_t* key = keys   + job.key_offset;
    const uint8_t* iv  = nonces + job.nonce_offset;

    // Key schedule.
    uint8_t rk[AES256_KS_BYTES];
    aes256_expand_key(key, rk);

    // H = AES_K(0^128).
    uint8_t H[16];
    {
        uint8_t zero[16];
        for (uint32_t i = 0u; i < 16u; ++i) zero[i] = 0u;
        aes256_encrypt_block(rk, zero, H);
    }

    // J0 = IV || 0x00000001 (96-bit IV path).
    uint8_t J0[16];
    for (uint32_t i = 0u; i < 12u; ++i) J0[i] = iv[i];
    J0[12] = 0u; J0[13] = 0u; J0[14] = 0u; J0[15] = 1u;

    // Encrypt plaintext under counter starting at inc32(J0).
    {
        uint8_t ctr[16];
        for (uint32_t i = 0u; i < 16u; ++i) ctr[i] = J0[i];
        inc32(ctr);

        uint32_t pos = 0u;
        while (pos < job.pt_len) {
            uint8_t ks[16];
            aes256_encrypt_block(rk, ctr, ks);
            uint32_t take = job.pt_len - pos;
            if (take > 16u) take = 16u;
            for (uint32_t i = 0u; i < take; ++i) {
                outputs_arena[job.ct_offset + pos + i] =
                    (uint8_t)(inputs_arena[job.pt_offset + pos + i] ^ ks[i]);
            }
            inc32(ctr);
            pos += take;
        }
    }

    // GHASH over (aad || pad || ct || pad || lens_in_bits).
    uint8_t Y[16];
    for (uint32_t i = 0u; i < 16u; ++i) Y[i] = 0u;
    ghash_update(Y, H, inputs_arena, job.aad_offset, job.aad_len);
    ghash_update(Y, H, outputs_arena, job.ct_offset, job.pt_len);
    {
        uint8_t lens[16];
        uint64_t la = (uint64_t)job.aad_len * 8ul;
        uint64_t lc = (uint64_t)job.pt_len  * 8ul;
        // BE encoding.
        for (uint32_t i = 0u; i < 8u; ++i) lens[i]      = (uint8_t)(la >> (8u * (7u - i)));
        for (uint32_t i = 0u; i < 8u; ++i) lens[8u + i] = (uint8_t)(lc >> (8u * (7u - i)));
        for (uint32_t i = 0u; i < 16u; ++i) Y[i] ^= lens[i];
        ghash_mul(Y, H);
    }

    // Tag = GHASH XOR AES_K(J0).
    {
        uint8_t s[16];
        aes256_encrypt_block(rk, J0, s);
        for (uint32_t i = 0u; i < 16u; ++i) {
            outputs_arena[job.tag_offset + i] = (uint8_t)(Y[i] ^ s[i]);
        }
    }
}

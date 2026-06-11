// GPU kernel for Lamport-SHA256 OTS — one thread per preimage. The kernel
// hashes each 32-byte slot independently with canonical FIPS 180-4 SHA-256
// padding (one 64-byte block: 32 input bytes, 0x80 marker, zero pad, 64-bit
// big-endian bit length = 256). The host driver supplies a flat preimage
// arena `slots` and reads a flat 32-byte digest arena `digests`.
//
// This is enough to bit-for-bit replay both Lamport keygen (sk slot -> pk slot)
// and Lamport verification (sig slot -> hash to compare against pk slot).
// Byte-equal to lamport/cpp/lamport.cpp.

#include <metal_stdlib>
using namespace metal;

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
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

inline uint rotr(uint x, uint n) { return (x >> n) | (x << (32u - n)); }
inline uint ch (uint x, uint y, uint z) { return (x & y) ^ ((~x) & z); }
inline uint maj(uint x, uint y, uint z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint S0 (uint x) { return rotr(x,  2) ^ rotr(x, 13) ^ rotr(x, 22); }
inline uint S1 (uint x) { return rotr(x,  6) ^ rotr(x, 11) ^ rotr(x, 25); }
inline uint s0 (uint x) { return rotr(x,  7) ^ rotr(x, 18) ^ (x >>  3); }
inline uint s1 (uint x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

kernel void lamport_hash_jobs(
    device const uchar* slots   [[buffer(0)]],   // 32 bytes per slot
    device       uchar* digests [[buffer(1)]],   // 32 bytes per slot
    constant uint& num_slots    [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= num_slots) return;

    device const uchar* in  = slots   + tid * 32u;
    device       uchar* out = digests + tid * 32u;

    // Canonical FIPS 180-4 padding for a 32-byte preimage:
    // single block, words 0..7 = input (BE), w[8] = 0x80000000, w[9..14] = 0,
    // w[15] = 256 (bit length).
    uint w[64];
    for (uint i = 0; i < 8u; ++i) {
        w[i] = (uint(in[i*4u + 0]) << 24)
             | (uint(in[i*4u + 1]) << 16)
             | (uint(in[i*4u + 2]) <<  8)
             | (uint(in[i*4u + 3])      );
    }
    w[ 8] = 0x80000000u;
    w[ 9] = 0u; w[10] = 0u; w[11] = 0u;
    w[12] = 0u; w[13] = 0u; w[14] = 0u;
    w[15] = 256u;
    for (uint i = 16u; i < 64u; ++i) {
        w[i] = s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16];
    }

    uint a = 0x6a09e667u, b = 0xbb67ae85u, c = 0x3c6ef372u, d = 0xa54ff53au;
    uint e = 0x510e527fu, f = 0x9b05688cu, g = 0x1f83d9abu, h = 0x5be0cd19u;

    for (uint i = 0; i < 64u; ++i) {
        uint t1 = h + S1(e) + ch(e, f, g) + K[i] + w[i];
        uint t2 = S0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    a += 0x6a09e667u; b += 0xbb67ae85u; c += 0x3c6ef372u; d += 0xa54ff53au;
    e += 0x510e527fu; f += 0x9b05688cu; g += 0x1f83d9abu; h += 0x5be0cd19u;

    uint H[8] = { a, b, c, d, e, f, g, h };
    for (uint i = 0; i < 8u; ++i) {
        out[i*4u + 0] = uchar((H[i] >> 24) & 0xFFu);
        out[i*4u + 1] = uchar((H[i] >> 16) & 0xFFu);
        out[i*4u + 2] = uchar((H[i] >>  8) & 0xFFu);
        out[i*4u + 3] = uchar( H[i]        & 0xFFu);
    }
}

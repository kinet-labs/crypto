// Host-side replay of the Lamport-SHA256 CUDA kernel arithmetic. Always built
// (no nvcc dependency). The CUDA determinism test runs the canonical CPU body
// (lamport/cpp/lamport.cpp) and asserts byte-equality against this oracle so
// the test exercises the kernel arithmetic on hosts without an NVIDIA device.
//
// On hosts with CUDA enabled, the same arithmetic also runs in
// `lamport_hash_jobs_kernel` (lamport/gpu/cuda/lamport.cu); both paths emit
// identical bytes by construction.

#include <cstdint>

namespace {

inline uint32_t lamport_rotr32_host(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32u - n));
}

inline void lamport_sha256_block_32_host(const uint8_t* in, uint8_t* out) {
    static const uint32_t K[64] = {
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

    uint32_t w[64];
    for (uint32_t i = 0; i < 8u; ++i) {
        w[i] = (uint32_t(in[i*4u + 0]) << 24)
             | (uint32_t(in[i*4u + 1]) << 16)
             | (uint32_t(in[i*4u + 2]) <<  8)
             | (uint32_t(in[i*4u + 3])      );
    }
    w[ 8] = 0x80000000u;
    w[ 9] = 0u; w[10] = 0u; w[11] = 0u;
    w[12] = 0u; w[13] = 0u; w[14] = 0u;
    w[15] = 256u;
    for (uint32_t i = 16u; i < 64u; ++i) {
        uint32_t s0 = lamport_rotr32_host(w[i-15],  7) ^ lamport_rotr32_host(w[i-15], 18) ^ (w[i-15] >>  3);
        uint32_t s1 = lamport_rotr32_host(w[i- 2], 17) ^ lamport_rotr32_host(w[i- 2], 19) ^ (w[i- 2] >> 10);
        w[i] = s1 + w[i-7] + s0 + w[i-16];
    }

    uint32_t a = 0x6a09e667u, b = 0xbb67ae85u, c = 0x3c6ef372u, d = 0xa54ff53au;
    uint32_t e = 0x510e527fu, f = 0x9b05688cu, g = 0x1f83d9abu, h = 0x5be0cd19u;

    for (uint32_t i = 0; i < 64u; ++i) {
        uint32_t S1 = lamport_rotr32_host(e,  6) ^ lamport_rotr32_host(e, 11) ^ lamport_rotr32_host(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = lamport_rotr32_host(a,  2) ^ lamport_rotr32_host(a, 13) ^ lamport_rotr32_host(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    a += 0x6a09e667u; b += 0xbb67ae85u; c += 0x3c6ef372u; d += 0xa54ff53au;
    e += 0x510e527fu; f += 0x9b05688cu; g += 0x1f83d9abu; h += 0x5be0cd19u;

    uint32_t H[8] = { a, b, c, d, e, f, g, h };
    for (uint32_t i = 0; i < 8u; ++i) {
        out[i*4u + 0] = uint8_t((H[i] >> 24) & 0xFFu);
        out[i*4u + 1] = uint8_t((H[i] >> 16) & 0xFFu);
        out[i*4u + 2] = uint8_t((H[i] >>  8) & 0xFFu);
        out[i*4u + 3] = uint8_t( H[i]        & 0xFFu);
    }
}

}  // namespace

extern "C" void lamport_hash_jobs_cuda_oracle(
    const uint8_t* slots,
    uint8_t*       digests,
    uint32_t       num_slots)
{
    for (uint32_t i = 0; i < num_slots; ++i) {
        lamport_sha256_block_32_host(slots + i * 32u, digests + i * 32u);
    }
}

// GPU-batched Keccak-256 (Ethereum, delimiter 0x01) using the KeccakJob[]
// shape. One thread per job; the job descriptor tells the thread where its
// input lives in the flat input buffer and where to write the 32-byte output.
//
// This kernel is byte-equal to keccak/cpp/keccak.cpp::keccak256(). For inputs
// >= rate (136 bytes) the absorb loop emits multiple blocks; padding is the
// canonical pad10*1 with delimiter 0x01.

#include <metal_stdlib>
using namespace metal;

constant ulong RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL,
    0x800000000000808AUL, 0x8000000080008000UL,
    0x000000000000808BUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008AUL, 0x0000000000000088UL,
    0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL,
    0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800AUL, 0x800000008000000AUL,
    0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL,
};

// Mod-64 rotation offsets matching keccak/cpp/keccak.cpp.
constant int R_OFFSETS[5][5] = {
    {  0, 36,  3, 41, 18},
    {  1, 44, 10, 45,  2},
    { 62,  6, 43, 15, 61},
    { 28, 55, 25, 21, 56},
    { 27, 20, 39,  8, 14},
};

inline ulong rotl64(ulong x, int n) {
    n &= 63;
    if (n == 0) return x;
    return (x << n) | (x >> (64 - n));
}

inline void keccakf1600(thread ulong* a) {
    ulong C[5], D[5], B[25];
    for (int round = 0; round < 24; ++round) {
        for (int x = 0; x < 5; ++x)
            C[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (int x = 0; x < 5; ++x)
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        for (int y = 0; y < 5; ++y)
            for (int x = 0; x < 5; ++x)
                a[x + 5 * y] ^= D[x];

        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y) {
                int nx = y;
                int ny = (2 * x + 3 * y) % 5;
                B[nx + 5 * ny] = rotl64(a[x + 5 * y], R_OFFSETS[x][y]);
            }

        for (int y = 0; y < 5; ++y) {
            ulong row[5];
            for (int x = 0; x < 5; ++x) row[x] = B[x + 5 * y];
            for (int x = 0; x < 5; ++x)
                a[x + 5 * y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5]);
        }

        a[0] ^= RC[round];
    }
}

// KeccakJob descriptor — must match crypto/keccak/cpp/keccak_service.hpp.
struct KeccakJobGPU {
    uint16_t kind;
    uint16_t input_offset_class;
    uint32_t input_offset;
    uint32_t input_len;
    uint32_t output_offset;
};

// Kernel: one thread per job.
kernel void keccak256_jobs(
    device const KeccakJobGPU* jobs    [[buffer(0)]],
    device const uchar*        inputs  [[buffer(1)]],
    device       uchar*        outputs [[buffer(2)]],
    constant uint& num_jobs            [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= num_jobs) return;

    KeccakJobGPU j = jobs[tid];
    const device uchar* in = inputs + j.input_offset;
    device uchar* out = outputs + j.output_offset;

    const uint RATE = 136;
    ulong state[25];
    for (int i = 0; i < 25; ++i) state[i] = 0;

    uint absorbed = 0;
    while (j.input_len - absorbed >= RATE) {
        for (uint w = 0; w < RATE / 8; ++w) {
            ulong lane = 0;
            for (uint b = 0; b < 8; ++b)
                lane |= ulong(in[absorbed + w * 8 + b]) << (b * 8);
            state[w] ^= lane;
        }
        keccakf1600(state);
        absorbed += RATE;
    }

    // Final block: copy tail + pad10*1 with delimiter 0x01.
    uchar block[136];
    for (uint i = 0; i < RATE; ++i) block[i] = 0;
    uint rem = j.input_len - absorbed;
    for (uint i = 0; i < rem; ++i) block[i] = in[absorbed + i];
    block[rem] = 0x01;
    block[RATE - 1] |= 0x80;

    for (uint w = 0; w < RATE / 8; ++w) {
        ulong lane = 0;
        for (uint b = 0; b < 8; ++b)
            lane |= ulong(block[w * 8 + b]) << (b * 8);
        state[w] ^= lane;
    }
    keccakf1600(state);

    // Squeeze 32 bytes.
    for (uint w = 0; w < 4; ++w) {
        ulong lane = state[w];
        for (uint b = 0; b < 8; ++b)
            out[w * 8 + b] = uchar(lane >> (b * 8));
    }
}

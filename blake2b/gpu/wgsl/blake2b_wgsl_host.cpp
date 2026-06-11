// Host-emulation translation of blake2b.wgsl. Each operation here mirrors
// the WGSL kernel one-for-one — same constants, same control flow, same
// vec2<u32>-emulated u64 arithmetic — so byte-equality with the CPU oracle
// proves the WGSL kernel will produce identical output on a real GPU.
//
// The wire format matches the kernel's bind group: data is uploaded as
// packed u32 (little-endian), inputs are HashInput descriptors, outputs
// are 16 u32 lanes per 64-byte digest. When a real wgpu host driver lands
// the body of `blake2b_batch_wgsl_host` is replaced by the dispatch path;
// the harness side stays unchanged.

#include <cstdint>
#include <cstring>
#include <vector>

namespace {

// =============================================================================
// IV (RFC 7693 sec 2.6) split (lo, hi).
// =============================================================================
constexpr uint32_t IV_LO[8] = {
    0xF3BCC908u, 0x84CAA73Bu, 0xFE94F82Bu, 0x5F1D36F1u,
    0xADE682D1u, 0x2B3E6C1Fu, 0xFB41BD6Bu, 0x137E2179u,
};
constexpr uint32_t IV_HI[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};

constexpr uint8_t SIGMA[10][16] = {
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
// 64-bit emulation primitives — identical to the WGSL helpers in blake2b.wgsl.
// =============================================================================
struct U64 { uint32_t lo; uint32_t hi; };

inline U64 xor64(U64 a, U64 b) { return U64{a.lo ^ b.lo, a.hi ^ b.hi}; }

inline U64 add64(U64 a, U64 b) {
    U64 r;
    r.lo = a.lo + b.lo;
    uint32_t carry = (r.lo < a.lo) ? 1u : 0u;
    r.hi = a.hi + b.hi + carry;
    return r;
}

inline U64 rotr64(U64 v, uint32_t n) {
    if (n == 0u)   return v;
    if (n == 32u)  return U64{v.hi, v.lo};
    if (n < 32u) {
        U64 r;
        r.lo = (v.lo >> n) | (v.hi << (32u - n));
        r.hi = (v.hi >> n) | (v.lo << (32u - n));
        return r;
    }
    uint32_t m = n - 32u;
    U64 r;
    r.lo = (v.hi >> m) | (v.lo << (32u - m));
    r.hi = (v.lo >> m) | (v.hi << (32u - m));
    return r;
}

inline U64 not64(U64 a) { return U64{~a.lo, ~a.hi}; }

inline uint32_t read_byte(const uint32_t* arena, uint32_t byte_offset) {
    uint32_t word_idx = byte_offset >> 2u;
    uint32_t byte_pos = byte_offset & 3u;
    return (arena[word_idx] >> (byte_pos * 8u)) & 0xFFu;
}

struct State {
    U64 v[16];
    U64 h[8];
    U64 m[16];
};

inline void g_mix(State& s, uint32_t a, uint32_t b, uint32_t c, uint32_t d,
                  uint32_t mx, uint32_t my) {
    s.v[a] = add64(add64(s.v[a], s.v[b]), s.m[mx]);
    s.v[d] = rotr64(xor64(s.v[d], s.v[a]), 32u);
    s.v[c] = add64(s.v[c], s.v[d]);
    s.v[b] = rotr64(xor64(s.v[b], s.v[c]), 24u);
    s.v[a] = add64(add64(s.v[a], s.v[b]), s.m[my]);
    s.v[d] = rotr64(xor64(s.v[d], s.v[a]), 16u);
    s.v[c] = add64(s.v[c], s.v[d]);
    s.v[b] = rotr64(xor64(s.v[b], s.v[c]), 63u);
}

inline void compress(State& s, U64 t0, U64 t1, bool last_block) {
    for (int i = 0; i < 8; ++i) s.v[i]     = s.h[i];
    for (int i = 0; i < 8; ++i) s.v[i + 8] = U64{IV_LO[i], IV_HI[i]};
    s.v[12] = xor64(s.v[12], t0);
    s.v[13] = xor64(s.v[13], t1);
    if (last_block) s.v[14] = not64(s.v[14]);

    for (int r = 0; r < 12; ++r) {
        const uint8_t* sig = SIGMA[r % 10];
        g_mix(s, 0, 4,  8, 12, sig[ 0], sig[ 1]);
        g_mix(s, 1, 5,  9, 13, sig[ 2], sig[ 3]);
        g_mix(s, 2, 6, 10, 14, sig[ 4], sig[ 5]);
        g_mix(s, 3, 7, 11, 15, sig[ 6], sig[ 7]);
        g_mix(s, 0, 5, 10, 15, sig[ 8], sig[ 9]);
        g_mix(s, 1, 6, 11, 12, sig[10], sig[11]);
        g_mix(s, 2, 7,  8, 13, sig[12], sig[13]);
        g_mix(s, 3, 4,  9, 14, sig[14], sig[15]);
    }
    for (int i = 0; i < 8; ++i) {
        s.h[i] = xor64(s.h[i], xor64(s.v[i], s.v[i + 8]));
    }
}

}  // namespace

// =============================================================================
// Public host entry — wire format matches the WGSL bind group: data is a
// flat byte arena (packed into u32 little-endian internally), per-input
// (offset, length) descriptors, and a 64-byte stride output buffer.
// =============================================================================
extern "C" int blake2b_batch_wgsl_host(
    const uint8_t*  data,
    size_t          data_len,
    const uint32_t* offsets,
    const uint32_t* lengths,
    uint8_t*        outputs,
    uint32_t        num_inputs)
{
    if (num_inputs == 0) return 0;
    if (!data || !offsets || !lengths || !outputs) return -1;

    // Pack into u32 words exactly the way wgpuQueueWriteBuffer would upload
    // the byte arena into a `array<u32>` storage buffer.
    size_t pad = (4 - (data_len & 3)) & 3;
    size_t word_count = (data_len + pad) / 4;
    if (word_count == 0) word_count = 1;
    std::vector<uint32_t> packed(word_count, 0u);
    if (data_len > 0) std::memcpy(packed.data(), data, data_len);

    for (uint32_t tid = 0; tid < num_inputs; ++tid) {
        uint32_t offset = offsets[tid];
        uint32_t len    = lengths[tid];

        State s{};
        for (int i = 0; i < 8; ++i) s.h[i] = U64{IV_LO[i], IV_HI[i]};
        s.h[0].lo ^= 0x01010040u;

        U64 t0{0u, 0u};
        U64 t1{0u, 0u};
        uint32_t pos = 0;

        while (len - pos > 128u) {
            for (int w = 0; w < 16; ++w) {
                uint32_t lo = 0, hi = 0;
                for (int b = 0; b < 4; ++b) {
                    lo |= read_byte(packed.data(), offset + pos + w * 8u + b) << (b * 8u);
                }
                for (int b = 0; b < 4; ++b) {
                    hi |= read_byte(packed.data(), offset + pos + w * 8u + 4u + b) << (b * 8u);
                }
                s.m[w] = U64{lo, hi};
            }
            pos += 128u;
            U64 t0_new = add64(t0, U64{128u, 0u});
            if (t0_new.hi < t0.hi) t1 = add64(t1, U64{1u, 0u});
            t0 = t0_new;
            compress(s, t0, t1, false);
        }

        const uint32_t rem = len - pos;
        for (int w = 0; w < 16; ++w) s.m[w] = U64{0u, 0u};
        for (uint32_t i = 0; i < rem; ++i) {
            uint32_t byte_val = read_byte(packed.data(), offset + pos + i);
            uint32_t word_idx = i >> 3u;
            uint32_t byte_in_word = i & 7u;
            if (byte_in_word < 4u) {
                s.m[word_idx].lo |= byte_val << (byte_in_word * 8u);
            } else {
                s.m[word_idx].hi |= byte_val << ((byte_in_word - 4u) * 8u);
            }
        }
        U64 t0_new = add64(t0, U64{rem, 0u});
        if (t0_new.hi < t0.hi) t1 = add64(t1, U64{1u, 0u});
        t0 = t0_new;
        compress(s, t0, t1, true);

        // Emit 64 bytes little-endian: each h[i] = (lo, hi) -> 8 bytes.
        uint8_t* out = outputs + tid * 64u;
        for (int i = 0; i < 8; ++i) {
            uint32_t lo = s.h[i].lo;
            uint32_t hi = s.h[i].hi;
            out[i * 8 + 0] = (uint8_t)(lo & 0xFFu);
            out[i * 8 + 1] = (uint8_t)((lo >>  8) & 0xFFu);
            out[i * 8 + 2] = (uint8_t)((lo >> 16) & 0xFFu);
            out[i * 8 + 3] = (uint8_t)((lo >> 24) & 0xFFu);
            out[i * 8 + 4] = (uint8_t)(hi & 0xFFu);
            out[i * 8 + 5] = (uint8_t)((hi >>  8) & 0xFFu);
            out[i * 8 + 6] = (uint8_t)((hi >> 16) & 0xFFu);
            out[i * 8 + 7] = (uint8_t)((hi >> 24) & 0xFFu);
        }
    }
    return 0;
}

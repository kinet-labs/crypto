// GPU-batched BLAKE3 (BLAKE3 spec). One thread per input. Byte-equal to
// blake3/cpp/blake3.cpp::hash() for arbitrary-length inputs.
//
// Each input is hashed in plain mode (key = IV, base flags = 0). Tree mode
// is implemented in-kernel: each chunk is processed sequentially per thread,
// chunk CVs are merged via a per-thread stack with the canonical "fold on
// trailing zero of total chunk count" rule, and the final root output is
// emitted with the ROOT flag.
//
// Layout: caller fills a Blake3Job[] with (input_offset, input_len,
// output_offset). Inputs share a flat byte arena; outputs share a 32-byte
// stride arena.

#include <metal_stdlib>
using namespace metal;

constant uint BLAKE3_IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};

constant uint CHUNK_START = 1u << 0;
constant uint CHUNK_END   = 1u << 1;
constant uint PARENT      = 1u << 2;
constant uint ROOT        = 1u << 3;

constant uchar MSG_PERM[16] = {
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
};

inline uint rotr32(uint x, uint n) {
    return (x >> n) | (x << (32u - n));
}

inline void g(thread uint* s, int a, int b, int c, int d,
              uint mx, uint my) {
    s[a] = s[a] + s[b] + mx;
    s[d] = rotr32(s[d] ^ s[a], 16u);
    s[c] = s[c] + s[d];
    s[b] = rotr32(s[b] ^ s[c], 12u);
    s[a] = s[a] + s[b] + my;
    s[d] = rotr32(s[d] ^ s[a], 8u);
    s[c] = s[c] + s[d];
    s[b] = rotr32(s[b] ^ s[c], 7u);
}

inline void round_fn(thread uint* s, thread uint* m) {
    g(s, 0, 4,  8, 12, m[0],  m[1]);
    g(s, 1, 5,  9, 13, m[2],  m[3]);
    g(s, 2, 6, 10, 14, m[4],  m[5]);
    g(s, 3, 7, 11, 15, m[6],  m[7]);
    g(s, 0, 5, 10, 15, m[8],  m[9]);
    g(s, 1, 6, 11, 12, m[10], m[11]);
    g(s, 2, 7,  8, 13, m[12], m[13]);
    g(s, 3, 4,  9, 14, m[14], m[15]);
}

inline void permute(thread uint* m) {
    uint tmp[16];
    for (int i = 0; i < 16; ++i) tmp[i] = m[MSG_PERM[i]];
    for (int i = 0; i < 16; ++i) m[i] = tmp[i];
}

// compress: writes 16 words to out_state. Caller takes [0..7] for chaining
// values, [0..15] for XOF blocks.
inline void compress(thread const uint* cv,
                     thread const uchar* block,
                     ulong counter,
                     uint block_len,
                     uint flags,
                     thread uint* out_state) {
    uint m[16];
    for (int i = 0; i < 16; ++i) {
        m[i] =  uint(block[i * 4 + 0])
             | (uint(block[i * 4 + 1]) << 8)
             | (uint(block[i * 4 + 2]) << 16)
             | (uint(block[i * 4 + 3]) << 24);
    }

    uint s[16] = {
        cv[0], cv[1], cv[2], cv[3],
        cv[4], cv[5], cv[6], cv[7],
        BLAKE3_IV[0], BLAKE3_IV[1], BLAKE3_IV[2], BLAKE3_IV[3],
        uint(counter & 0xFFFFFFFFu),
        uint(counter >> 32),
        block_len,
        flags,
    };

    round_fn(s, m); permute(m);
    round_fn(s, m); permute(m);
    round_fn(s, m); permute(m);
    round_fn(s, m); permute(m);
    round_fn(s, m); permute(m);
    round_fn(s, m); permute(m);
    round_fn(s, m);

    for (int i = 0; i < 8; ++i) {
        out_state[i]     = s[i] ^ s[i + 8];
        out_state[i + 8] = s[i + 8] ^ cv[i];
    }
}

struct Blake3Job {
    uint input_offset;
    uint input_len;
    uint output_offset;
    uint _pad;
};

// Per-thread chunk state.
struct ChunkState {
    uint  cv[8];
    ulong chunk_counter;
    uchar block[64];
    uint  block_len;          // 0..64
    uint  blocks_compressed;  // 0..15 mid-chunk
    uint  flags;
};

inline void chunk_init(thread ChunkState& cs, ulong cc, uint base_flags) {
    for (int i = 0; i < 8; ++i) cs.cv[i] = BLAKE3_IV[i];
    cs.chunk_counter = cc;
    for (int i = 0; i < 64; ++i) cs.block[i] = 0;
    cs.block_len = 0u;
    cs.blocks_compressed = 0u;
    cs.flags = base_flags;
}

inline uint chunk_start_flag(thread const ChunkState& cs) {
    return cs.blocks_compressed == 0u ? CHUNK_START : 0u;
}

inline uint chunk_len(thread const ChunkState& cs) {
    return 64u * cs.blocks_compressed + cs.block_len;
}

inline void chunk_update(thread ChunkState& cs,
                         device const uchar* data, uint pos, uint count) {
    uint i = 0u;
    while (i < count) {
        if (cs.block_len == 64u) {
            uint s[16];
            uchar tb[64];
            for (int k = 0; k < 64; ++k) tb[k] = cs.block[k];
            compress(cs.cv, tb, cs.chunk_counter, 64u,
                     cs.flags | chunk_start_flag(cs), s);
            for (int k = 0; k < 8; ++k) cs.cv[k] = s[k];
            cs.blocks_compressed += 1u;
            for (int k = 0; k < 64; ++k) cs.block[k] = 0;
            cs.block_len = 0u;
        }
        uint want = 64u - cs.block_len;
        uint take = (count - i < want) ? (count - i) : want;
        for (uint k = 0u; k < take; ++k) {
            cs.block[cs.block_len + k] = data[pos + i + k];
        }
        cs.block_len += take;
        i += take;
    }
}

// Compute chunk CV (non-root). Reads cs by-thread copy.
inline void chunk_chaining_value(thread const ChunkState& cs, thread uint* out) {
    uint s[16];
    uchar tb[64];
    for (int k = 0; k < 64; ++k) tb[k] = cs.block[k];
    uint flags = cs.flags | chunk_start_flag(cs) | CHUNK_END;
    compress(cs.cv, tb, cs.chunk_counter, cs.block_len, flags, s);
    for (int k = 0; k < 8; ++k) out[k] = s[k];
}

inline void parent_block(thread const uint* l, thread const uint* r,
                         thread uchar* out) {
    for (int i = 0; i < 8; ++i) {
        uint w = l[i];
        out[i * 4 + 0] = uchar(w & 0xFFu);
        out[i * 4 + 1] = uchar((w >> 8) & 0xFFu);
        out[i * 4 + 2] = uchar((w >> 16) & 0xFFu);
        out[i * 4 + 3] = uchar((w >> 24) & 0xFFu);
    }
    for (int i = 0; i < 8; ++i) {
        uint w = r[i];
        out[32 + i * 4 + 0] = uchar(w & 0xFFu);
        out[32 + i * 4 + 1] = uchar((w >> 8) & 0xFFu);
        out[32 + i * 4 + 2] = uchar((w >> 16) & 0xFFu);
        out[32 + i * 4 + 3] = uchar((w >> 24) & 0xFFu);
    }
}

inline void parent_cv_compute(thread const uint* l, thread const uint* r,
                              uint base_flags, thread uint* out) {
    uchar pb[64];
    parent_block(l, r, pb);
    uint s[16];
    uint kw[8];
    for (int i = 0; i < 8; ++i) kw[i] = BLAKE3_IV[i];
    compress(kw, pb, 0ul, 64u, PARENT | base_flags, s);
    for (int i = 0; i < 8; ++i) out[i] = s[i];
}

// Stack-of-CVs Bao tree, max depth 54 covers 2^54 chunks.
constant uint BLAKE3_STACK_MAX = 54u;

kernel void blake3_jobs(
    device const Blake3Job* jobs    [[buffer(0)]],
    device const uchar*     inputs  [[buffer(1)]],
    device       uchar*     outputs [[buffer(2)]],
    constant uint&          num_jobs [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= num_jobs) return;

    Blake3Job j = jobs[tid];
    uint base_flags = 0u;

    // Single-chunk fast path: rare but common for short messages.
    if (j.input_len <= 1024u) {
        ChunkState cs;
        chunk_init(cs, 0ul, base_flags);
        chunk_update(cs, inputs, j.input_offset, j.input_len);

        // Root output: 16 words from compressing this chunk's final state
        // with ROOT flag. For 32-byte digest we only emit the first 8 words.
        uint s[16];
        uchar tb[64];
        for (int k = 0; k < 64; ++k) tb[k] = cs.block[k];
        uint flags = cs.flags | chunk_start_flag(cs) | CHUNK_END | ROOT;
        compress(cs.cv, tb, cs.chunk_counter, cs.block_len, flags, s);

        device uchar* dst = outputs + j.output_offset;
        for (int i = 0; i < 8; ++i) {
            uint w = s[i];
            dst[i * 4 + 0] = uchar(w & 0xFFu);
            dst[i * 4 + 1] = uchar((w >> 8) & 0xFFu);
            dst[i * 4 + 2] = uchar((w >> 16) & 0xFFu);
            dst[i * 4 + 3] = uchar((w >> 24) & 0xFFu);
        }
        return;
    }

    // Multi-chunk: stack-of-CVs tree mode.
    uint stack[BLAKE3_STACK_MAX][8];
    uint stack_len = 0u;

    ChunkState cs;
    chunk_init(cs, 0ul, base_flags);
    uint pos = 0u;
    while (pos < j.input_len) {
        if (chunk_len(cs) == 1024u) {
            // Finish this chunk → push CV.
            uint cv[8];
            chunk_chaining_value(cs, cv);
            ulong this_idx = cs.chunk_counter;
            // Merge while the trailing bit of (this_idx + 1) is 0.
            ulong total = this_idx + 1ul;
            uint cur[8];
            for (int k = 0; k < 8; ++k) cur[k] = cv[k];
            while ((total & 1ul) == 0ul) {
                uint left[8];
                for (int k = 0; k < 8; ++k) left[k] = stack[stack_len - 1u][k];
                uint merged[8];
                parent_cv_compute(left, cur, base_flags, merged);
                for (int k = 0; k < 8; ++k) cur[k] = merged[k];
                stack_len -= 1u;
                total >>= 1ul;
            }
            for (int k = 0; k < 8; ++k) stack[stack_len][k] = cur[k];
            stack_len += 1u;
            chunk_init(cs, this_idx + 1ul, base_flags);
        }
        uint want = 1024u - chunk_len(cs);
        uint take = (j.input_len - pos < want) ? (j.input_len - pos) : want;
        chunk_update(cs, inputs, j.input_offset + pos, take);
        pos += take;
    }

    // Finalize: walk stack folding right with current chunk's output.
    // The very last merge gets ROOT flag.
    if (stack_len == 0u) {
        // Should not reach here in multi-chunk path; handle defensively.
        uint s[16];
        uchar tb[64];
        for (int k = 0; k < 64; ++k) tb[k] = cs.block[k];
        uint flags = cs.flags | chunk_start_flag(cs) | CHUNK_END | ROOT;
        compress(cs.cv, tb, cs.chunk_counter, cs.block_len, flags, s);
        device uchar* dst = outputs + j.output_offset;
        for (int i = 0; i < 8; ++i) {
            uint w = s[i];
            dst[i * 4 + 0] = uchar(w & 0xFFu);
            dst[i * 4 + 1] = uchar((w >> 8) & 0xFFu);
            dst[i * 4 + 2] = uchar((w >> 16) & 0xFFu);
            dst[i * 4 + 3] = uchar((w >> 24) & 0xFFu);
        }
        return;
    }

    // Get current chunk's CV (non-root for now; root applied at last merge).
    uint cur_cv[8];
    chunk_chaining_value(cs, cur_cv);

    // Walk stack from top down. The final merge replaces parent_cv_compute
    // with a ROOT-flagged compress emitting the digest directly.
    int idx = int(stack_len) - 1;
    while (idx >= 0) {
        uint left[8];
        for (int k = 0; k < 8; ++k) left[k] = stack[idx][k];
        if (idx == 0) {
            // Root parent: ROOT-flagged compress, take first 8 words.
            uchar pb[64];
            parent_block(left, cur_cv, pb);
            uint s[16];
            uint kw[8];
            for (int k = 0; k < 8; ++k) kw[k] = BLAKE3_IV[k];
            compress(kw, pb, 0ul, 64u, PARENT | base_flags | ROOT, s);
            device uchar* dst = outputs + j.output_offset;
            for (int i = 0; i < 8; ++i) {
                uint w = s[i];
                dst[i * 4 + 0] = uchar(w & 0xFFu);
                dst[i * 4 + 1] = uchar((w >> 8) & 0xFFu);
                dst[i * 4 + 2] = uchar((w >> 16) & 0xFFu);
                dst[i * 4 + 3] = uchar((w >> 24) & 0xFFu);
            }
            return;
        }
        uint merged[8];
        parent_cv_compute(left, cur_cv, base_flags, merged);
        for (int k = 0; k < 8; ++k) cur_cv[k] = merged[k];
        idx -= 1;
    }
}

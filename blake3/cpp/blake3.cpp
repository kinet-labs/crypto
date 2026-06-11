// First-party BLAKE3 implementation, faithful to the BLAKE3 spec
// (https://github.com/BLAKE3-team/BLAKE3-spec). Single-threaded, no SIMD, no
// vendored upstream code. Verified byte-equal to the official KAT
// (test_vectors.json, 35 input lengths from 0 to 102400 bytes) across all
// three modes (hash, keyed_hash, derive_key) and against XOF outputs.

#include "blake3.hpp"

#include <array>
#include <cstring>

namespace kinet::crypto::blake3 {

namespace {

// Spec section 2.1: initialization vector (SHA-256 IV).
constexpr uint32_t IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};

// Spec section 2.1: domain separation flags.
constexpr uint32_t CHUNK_START         = 1u << 0;
constexpr uint32_t CHUNK_END           = 1u << 1;
constexpr uint32_t PARENT              = 1u << 2;
constexpr uint32_t ROOT                = 1u << 3;
constexpr uint32_t KEYED_HASH          = 1u << 4;
constexpr uint32_t DERIVE_KEY_CONTEXT  = 1u << 5;
constexpr uint32_t DERIVE_KEY_MATERIAL = 1u << 6;

// Message-word permutation applied between the 7 rounds (spec section 2.5).
constexpr uint8_t MSG_PERM[16] = {
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
};

inline uint32_t rotr32(uint32_t x, uint32_t n) noexcept {
    return (x >> n) | (x << (32u - n));
}

// G(state, a, b, c, d, mx, my). Spec section 2.4.
inline void g(uint32_t s[16], int a, int b, int c, int d,
              uint32_t mx, uint32_t my) noexcept {
    s[a] = s[a] + s[b] + mx;
    s[d] = rotr32(s[d] ^ s[a], 16);
    s[c] = s[c] + s[d];
    s[b] = rotr32(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my;
    s[d] = rotr32(s[d] ^ s[a], 8);
    s[c] = s[c] + s[d];
    s[b] = rotr32(s[b] ^ s[c], 7);
}

// One BLAKE3 round: column then diagonal G operations (spec section 2.4).
inline void round_fn(uint32_t s[16], const uint32_t m[16]) noexcept {
    g(s, 0, 4,  8, 12, m[0],  m[1]);
    g(s, 1, 5,  9, 13, m[2],  m[3]);
    g(s, 2, 6, 10, 14, m[4],  m[5]);
    g(s, 3, 7, 11, 15, m[6],  m[7]);
    g(s, 0, 5, 10, 15, m[8],  m[9]);
    g(s, 1, 6, 11, 12, m[10], m[11]);
    g(s, 2, 7,  8, 13, m[12], m[13]);
    g(s, 3, 4,  9, 14, m[14], m[15]);
}

inline void permute(uint32_t m[16]) noexcept {
    uint32_t tmp[16];
    for (int i = 0; i < 16; ++i) tmp[i] = m[MSG_PERM[i]];
    std::memcpy(m, tmp, sizeof(tmp));
}

// Compression function (spec section 2.3). Writes the full 16-word state to
// `out_state`; callers extract either the first 8 words (for chaining values)
// or all 16 (for XOF output).
inline void compress(const uint32_t cv[8],
                     const uint8_t block[BLOCK_LEN],
                     uint64_t counter,
                     uint32_t block_len,
                     uint32_t flags,
                     uint32_t out_state[16]) noexcept {
    uint32_t m[16];
    for (int i = 0; i < 16; ++i) {
        m[i] =  uint32_t(block[i * 4 + 0])
             | (uint32_t(block[i * 4 + 1]) << 8)
             | (uint32_t(block[i * 4 + 2]) << 16)
             | (uint32_t(block[i * 4 + 3]) << 24);
    }

    uint32_t s[16] = {
        cv[0], cv[1], cv[2], cv[3],
        cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        uint32_t(counter & 0xFFFFFFFFu),
        uint32_t(counter >> 32),
        block_len,
        flags,
    };

    round_fn(s, m); permute(m);  // round 1
    round_fn(s, m); permute(m);  // round 2
    round_fn(s, m); permute(m);  // round 3
    round_fn(s, m); permute(m);  // round 4
    round_fn(s, m); permute(m);  // round 5
    round_fn(s, m); permute(m);  // round 6
    round_fn(s, m);              // round 7 (no final permute)

    for (int i = 0; i < 8; ++i) {
        out_state[i]     = s[i] ^ s[i + 8];
        out_state[i + 8] = s[i + 8] ^ cv[i];
    }
}

// Output struct: holds the inputs needed to re-run compression on demand,
// supporting both 32-byte chaining values and arbitrary-length XOF (spec
// section 4: tree mode + root XOF).
struct Output {
    uint32_t input_cv[8];
    uint8_t  block[BLOCK_LEN];
    uint64_t counter;
    uint32_t block_len;
    uint32_t flags;

    // 8-word chaining value (non-root output).
    void chaining_value(uint32_t out[8]) const noexcept {
        uint32_t s[16];
        compress(input_cv, block, counter, block_len, flags, s);
        for (int i = 0; i < 8; ++i) out[i] = s[i];
    }

    // XOF: extract any number of bytes by re-running compression with the
    // ROOT flag and an incrementing output-block counter.
    void root_bytes(uint8_t* out, std::size_t out_len) const noexcept {
        uint64_t out_counter = 0;
        std::size_t pos = 0;
        while (pos < out_len) {
            uint32_t s[16];
            compress(input_cv, block, out_counter, block_len,
                     flags | ROOT, s);
            std::size_t to_copy = (out_len - pos < BLOCK_LEN)
                                ? (out_len - pos) : BLOCK_LEN;
            for (std::size_t i = 0; i < to_copy; ++i) {
                uint32_t w = s[i / 4];
                out[pos + i] = uint8_t((w >> (8 * (i % 4))) & 0xFFu);
            }
            pos += to_copy;
            ++out_counter;
        }
    }
};

// ChunkState: incrementally absorbs up to CHUNK_LEN bytes for a single chunk.
// (Spec section 5.2.) The caller is responsible for tracking chunk_counter.
struct ChunkState {
    uint32_t cv[8];
    uint64_t chunk_counter;
    uint8_t  block[BLOCK_LEN];
    uint8_t  block_len;       // bytes currently in `block`
    uint8_t  blocks_compressed;
    uint32_t flags;

    void init(const uint32_t key_words[8], uint64_t cc, uint32_t f) noexcept {
        for (int i = 0; i < 8; ++i) cv[i] = key_words[i];
        chunk_counter = cc;
        std::memset(block, 0, BLOCK_LEN);
        block_len = 0;
        blocks_compressed = 0;
        flags = f;
    }

    std::size_t len() const noexcept {
        return std::size_t(BLOCK_LEN) * blocks_compressed + block_len;
    }

    uint32_t start_flag() const noexcept {
        return blocks_compressed == 0 ? CHUNK_START : 0u;
    }

    void update(const uint8_t* in, std::size_t in_len) noexcept {
        while (in_len > 0) {
            // Block full: compress, reset.
            if (block_len == BLOCK_LEN) {
                uint32_t s[16];
                compress(cv, block, chunk_counter, BLOCK_LEN,
                         flags | start_flag(), s);
                for (int i = 0; i < 8; ++i) cv[i] = s[i];
                ++blocks_compressed;
                std::memset(block, 0, BLOCK_LEN);
                block_len = 0;
            }
            std::size_t want = BLOCK_LEN - block_len;
            std::size_t take = in_len < want ? in_len : want;
            std::memcpy(block + block_len, in, take);
            block_len += uint8_t(take);
            in += take;
            in_len -= take;
        }
    }

    Output output() const noexcept {
        Output o{};
        for (int i = 0; i < 8; ++i) o.input_cv[i] = cv[i];
        std::memcpy(o.block, block, BLOCK_LEN);
        o.counter = chunk_counter;
        o.block_len = block_len;
        o.flags = flags | start_flag() | CHUNK_END;
        return o;
    }
};

// Parent output for two child chaining values (spec section 5.3).
inline Output parent_output(const uint32_t left_cv[8],
                            const uint32_t right_cv[8],
                            const uint32_t key_words[8],
                            uint32_t flags) noexcept {
    Output o{};
    for (int i = 0; i < 8; ++i) o.input_cv[i] = key_words[i];
    for (int i = 0; i < 8; ++i) {
        uint32_t w = left_cv[i];
        o.block[i * 4 + 0] = uint8_t(w >> 0);
        o.block[i * 4 + 1] = uint8_t(w >> 8);
        o.block[i * 4 + 2] = uint8_t(w >> 16);
        o.block[i * 4 + 3] = uint8_t(w >> 24);
    }
    for (int i = 0; i < 8; ++i) {
        uint32_t w = right_cv[i];
        o.block[32 + i * 4 + 0] = uint8_t(w >> 0);
        o.block[32 + i * 4 + 1] = uint8_t(w >> 8);
        o.block[32 + i * 4 + 2] = uint8_t(w >> 16);
        o.block[32 + i * 4 + 3] = uint8_t(w >> 24);
    }
    o.counter = 0;
    o.block_len = BLOCK_LEN;
    o.flags = PARENT | flags;
    return o;
}

inline void parent_cv(const uint32_t left_cv[8],
                      const uint32_t right_cv[8],
                      const uint32_t key_words[8],
                      uint32_t flags,
                      uint32_t out[8]) noexcept {
    parent_output(left_cv, right_cv, key_words, flags).chaining_value(out);
}

// Hasher: tree-mode hashing (spec section 5.1). Stack-of-CVs Bao tree.
struct Hasher {
    ChunkState chunk_state;
    uint32_t   key_words[8];
    // Stack of subtree CVs, indexed by complete-subtree depth.
    std::array<std::array<uint32_t, 8>, 54> cv_stack;  // log2(2^54 chunks) headroom
    uint8_t    cv_stack_len;
    uint32_t   flags;

    void init(const uint32_t kw[8], uint32_t f) noexcept {
        chunk_state.init(kw, 0, f);
        for (int i = 0; i < 8; ++i) key_words[i] = kw[i];
        cv_stack_len = 0;
        flags = f;
    }

    void push_cv(const uint32_t cv[8], uint64_t total_chunks_after_this) noexcept {
        // Spec section 5.1.2: merge complete subtrees lazily based on the
        // count of chunks finalized so far. After pushing the new CV, we may
        // need to merge subtrees: each trailing-zero bit in the *previous*
        // count tells us the height of subtrees to merge (left).
        // We use the technique of looking at the post-push chunk count.
        std::array<uint32_t, 8> tmp;
        for (int i = 0; i < 8; ++i) tmp[i] = cv[i];
        uint64_t total = total_chunks_after_this;
        // While the lowest bit of total_chunks is 0, merge.
        while ((total & 1) == 0) {
            uint32_t merged[8];
            parent_cv(cv_stack[cv_stack_len - 1].data(), tmp.data(),
                      key_words, flags, merged);
            for (int i = 0; i < 8; ++i) tmp[i] = merged[i];
            --cv_stack_len;
            total >>= 1;
        }
        cv_stack[cv_stack_len] = tmp;
        ++cv_stack_len;
    }

    void update(const uint8_t* in, std::size_t in_len) noexcept {
        while (in_len > 0) {
            if (chunk_state.len() == CHUNK_LEN) {
                uint32_t cv[8];
                chunk_state.output().chaining_value(cv);
                uint64_t this_idx = chunk_state.chunk_counter;
                push_cv(cv, this_idx + 1);
                chunk_state.init(key_words, this_idx + 1, flags);
            }
            std::size_t want = CHUNK_LEN - chunk_state.len();
            std::size_t take = in_len < want ? in_len : want;
            chunk_state.update(in, take);
            in += take;
            in_len -= take;
        }
    }

    void finalize(uint8_t* out, std::size_t out_len) const noexcept {
        // If only one chunk has been written, that chunk's output IS the
        // root.
        if (cv_stack_len == 0) {
            chunk_state.output().root_bytes(out, out_len);
            return;
        }
        // Otherwise, fold the stack right-to-left, last entry being the
        // current chunk's output, then merge upward.
        Output current = chunk_state.output();
        uint32_t cv[8];
        current.chaining_value(cv);

        // Walk stack from top → bottom merging.
        int idx = cv_stack_len - 1;
        while (idx >= 0) {
            // Merge cv_stack[idx] (left) with cv (right). The last merge is
            // root.
            if (idx == 0) {
                // Root parent: emit XOF directly.
                Output root = parent_output(cv_stack[0].data(), cv,
                                            key_words, flags);
                root.root_bytes(out, out_len);
                return;
            }
            uint32_t merged[8];
            parent_cv(cv_stack[idx].data(), cv, key_words, flags, merged);
            for (int i = 0; i < 8; ++i) cv[i] = merged[i];
            --idx;
        }
        // Unreachable: cv_stack_len >= 1 implies idx hits 0 above.
    }
};

inline void key_to_words(const uint8_t key[KEY_LEN], uint32_t words[8]) noexcept {
    for (int i = 0; i < 8; ++i) {
        words[i] =  uint32_t(key[i * 4 + 0])
                 | (uint32_t(key[i * 4 + 1]) << 8)
                 | (uint32_t(key[i * 4 + 2]) << 16)
                 | (uint32_t(key[i * 4 + 3]) << 24);
    }
}

}  // namespace

void hash(const uint8_t* in, std::size_t in_len,
          uint8_t* out, std::size_t out_len) noexcept {
    Hasher h;
    h.init(IV, 0);
    h.update(in, in_len);
    h.finalize(out, out_len);
}

void keyed_hash(const uint8_t key[KEY_LEN],
                const uint8_t* in, std::size_t in_len,
                uint8_t* out, std::size_t out_len) noexcept {
    uint32_t kw[8];
    key_to_words(key, kw);
    Hasher h;
    h.init(kw, KEYED_HASH);
    h.update(in, in_len);
    h.finalize(out, out_len);
}

void derive_key(const char* context_str, std::size_t context_str_len,
                const uint8_t* key_material, std::size_t key_material_len,
                uint8_t* out, std::size_t out_len) noexcept {
    // Step 1: hash context string with DERIVE_KEY_CONTEXT, IV as key.
    Hasher ctx_hasher;
    ctx_hasher.init(IV, DERIVE_KEY_CONTEXT);
    ctx_hasher.update(reinterpret_cast<const uint8_t*>(context_str),
                      context_str_len);
    uint8_t ctx_key[KEY_LEN];
    ctx_hasher.finalize(ctx_key, KEY_LEN);

    // Step 2: hash key material with DERIVE_KEY_MATERIAL, derived ctx_key.
    uint32_t ctx_words[8];
    key_to_words(ctx_key, ctx_words);
    Hasher h;
    h.init(ctx_words, DERIVE_KEY_MATERIAL);
    h.update(key_material, key_material_len);
    h.finalize(out, out_len);
}

}  // namespace kinet::crypto::blake3

// Fiat-Shamir transcript root -- CPU reference.
//
// Uses Keccak-256 over the concatenation of:
//   domain_sep || data
// where domain_sep is null-terminated ASCII (terminator excluded). The
// encoding is a single one-shot keccak256 -- this matches what most STARK
// transcripts do with sponge "absorb everything, squeeze 32" semantics.
//
// State layout:
//   opaque[0..7]   : in-progress length (u64 LE)
//   opaque[8..15]  : reserved
//   opaque[16..]   : queued absorb bytes (overflow grows via heap if needed)
//
// For simplicity and byte-equality with GPU drivers, the streaming API just
// accumulates into a vector via the reserved tail; finalize hashes it with
// keccak256.

#include "kinet/gpukit/transcript_root.h"
#include "kinet/crypto/keccak.h"
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

struct State {
    std::vector<uint8_t> buf;
};

// We keep the State on the heap, indexed by a pointer stored in opaque[0..7].
inline State* get_state(gpukit_transcript* t, bool create) {
    void* p = nullptr;
    std::memcpy(&p, t->opaque, sizeof(p));
    if (!p && create) {
        State* s = new State();
        std::memcpy(t->opaque, &s, sizeof(s));
        return s;
    }
    return reinterpret_cast<State*>(p);
}

}  // namespace

extern "C" void gpukit_transcript_init_cpu(gpukit_transcript* t,
                                           const char* domain_sep) {
    std::memset(t->opaque, 0, sizeof(t->opaque));
    State* s = get_state(t, true);
    if (domain_sep) {
        size_t L = std::strlen(domain_sep);
        s->buf.insert(s->buf.end(),
                      reinterpret_cast<const uint8_t*>(domain_sep),
                      reinterpret_cast<const uint8_t*>(domain_sep) + L);
    }
}

extern "C" void gpukit_transcript_append_cpu(gpukit_transcript* t,
                                             const uint8_t* data, size_t n) {
    State* s = get_state(t, true);
    if (data && n) {
        s->buf.insert(s->buf.end(), data, data + n);
    }
}

extern "C" void gpukit_transcript_finalize_cpu(gpukit_transcript* t,
                                               uint8_t out_root[32]) {
    State* s = get_state(t, false);
    if (!s) {
        std::memset(out_root, 0, 32);
        return;
    }
    keccak256(s->buf.data(), s->buf.size(), out_root);
    delete s;
    std::memset(t->opaque, 0, sizeof(t->opaque));
}

extern "C" void gpukit_transcript_root_cpu(const char* domain_sep,
                                           const uint8_t* data, size_t n,
                                           uint8_t out_root[32]) {
    gpukit_transcript t;
    gpukit_transcript_init_cpu(&t, domain_sep);
    gpukit_transcript_append_cpu(&t, data, n);
    gpukit_transcript_finalize_cpu(&t, out_root);
}

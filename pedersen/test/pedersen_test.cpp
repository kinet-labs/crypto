// pedersen scaffold test. The byte-equal commit body is blocked on the
// BN254 G1 backend, so this test asserts the input-validation contract:
//   - 10+ KAT vectors of malformed input get rejected as kStatusInvalidInput
//   - 10+ KAT vectors of well-formed input return kStatusNotImplemented
//     (NOT silently 0, which would be a false positive)
//
// When the BN254 backend lands, the well-formed path must transition from
// kStatusNotImplemented to kStatusOK with byte-equal output to the Go KATs.

#include "pedersen.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

using kinet::crypto::pedersen::G1Affine;
using kinet::crypto::pedersen::Generators;
using kinet::crypto::pedersen::CommitInput;
using kinet::crypto::pedersen::commit_batch;
using kinet::crypto::pedersen::kStatusOK;
using kinet::crypto::pedersen::kStatusInvalidInput;
using kinet::crypto::pedersen::kStatusNotImplemented;

static int failures = 0;
static int tests = 0;
#define EXPECT(cond, fmt, ...) do { \
    ++tests; \
    if (!(cond)) { \
        ++failures; \
        std::fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    } \
} while (0)

static Generators dummy_generators() {
    Generators g{};
    // Non-zero placeholder bytes; validation does not inspect curve membership.
    for (int i = 0; i < 32; ++i) {
        g.G.x[i] = uint8_t(i + 1);
        g.G.y[i] = uint8_t(0x80 + i);
        g.H.x[i] = uint8_t(0x40 + i);
        g.H.y[i] = uint8_t(0xC0 + i);
    }
    return g;
}

int main() {
    auto gens = dummy_generators();

    // 10 malformed inputs (high byte >= 0x31 in either scalar).
    struct Bad { uint8_t mhi, rhi; const char* name; };
    static const Bad bad_cases[] = {
        {0x31, 0x00, "m_hi=0x31"},
        {0xFF, 0x00, "m_hi=0xFF"},
        {0x00, 0x31, "r_hi=0x31"},
        {0x00, 0xFF, "r_hi=0xFF"},
        {0x31, 0x31, "both 0x31"},
        {0x80, 0x80, "both 0x80"},
        {0xFE, 0xFE, "both 0xFE"},
        {0x40, 0x00, "m_hi=0x40"},
        {0x00, 0x40, "r_hi=0x40"},
        {0x60, 0x60, "both 0x60"},
    };
    for (const auto& tc : bad_cases) {
        CommitInput in{};
        in.m[0] = tc.mhi;
        in.r[0] = tc.rhi;
        G1Affine out{};
        int rc = commit_batch(gens, &in, 1, &out);
        EXPECT(rc == kStatusInvalidInput,
               "bad %s: got rc=%d, want kStatusInvalidInput", tc.name, rc);
    }

    // 10 well-formed inputs (high byte < 0x30): MUST return NOTIMPL.
    for (int i = 0; i < 10; ++i) {
        CommitInput in{};
        // Cap m_hi and r_hi to <= 0x2F.
        in.m[0] = uint8_t(i & 0x2F);
        in.r[0] = uint8_t((i + 7) & 0x2F);
        for (int b = 1; b < 32; ++b) {
            in.m[b] = uint8_t(b * (i + 1) % 251);
            in.r[b] = uint8_t(b * (i + 11) % 251);
        }
        G1Affine out{};
        // Pre-poison the output so we can assert it gets zeroed by the
        // not-implemented path.
        std::memset(&out, 0xAB, sizeof(out));
        int rc = commit_batch(gens, &in, 1, &out);
        EXPECT(rc == kStatusNotImplemented,
               "well-formed %d: got rc=%d, want kStatusNotImplemented", i, rc);
        // Output must have been zeroed.
        bool zeroed = true;
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&out);
        for (size_t b = 0; b < sizeof(out); ++b) {
            if (p[b] != 0) { zeroed = false; break; }
        }
        EXPECT(zeroed, "well-formed %d: output not zeroed", i);
    }

    // Null pointer / zero-count rejected.
    {
        G1Affine out{};
        EXPECT(commit_batch(gens, nullptr, 1, &out) == kStatusInvalidInput,
               "null inputs not rejected");
        CommitInput in{};
        EXPECT(commit_batch(gens, &in, 0, &out) == kStatusInvalidInput,
               "count=0 not rejected");
        EXPECT(commit_batch(gens, &in, 1, nullptr) == kStatusInvalidInput,
               "null out not rejected");
    }

    std::printf("pedersen: %d/%d passed\n", tests - failures, tests);
    return failures == 0 ? 0 : 1;
}

// ipa scaffold test: 10+ malformed and 10+ well-formed KAT vectors. Every
// well-formed input MUST return kStatusNotImplemented (not 0) until the
// Banderwagon backend lands; the transition from NOTIMPL to OK is the
// signal that the byte-equal port is live.

#include "ipa.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

using namespace kinet::crypto::ipa;

static int failures = 0;
static int tests = 0;
#define EXPECT(cond, fmt, ...) do { \
    ++tests; \
    if (!(cond)) { \
        ++failures; \
        std::fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    } \
} while (0)

int main() {
    // Build a well-formed proof view (data and openings are dummy bytes;
    // validation does not check curve membership).
    static uint8_t fake_proof_bytes[1024] = {1, 2, 3, 4};

    OpeningView openings[3];
    std::memset(openings, 0, sizeof(openings));
    openings[0].z = 0;
    openings[1].z = 7;
    openings[2].z = 255;
    BatchProofView good = {{fake_proof_bytes, sizeof(fake_proof_bytes)},
                            openings, 3};

    // 10+ malformed inputs.
    {
        // null array
        EXPECT(verify_batch(nullptr, 1) == kStatusInvalidInput, "null proofs");
        // zero count
        EXPECT(verify_batch(&good, 0) == kStatusInvalidInput, "zero count");
        // null proof data
        BatchProofView bp = good;
        bp.proof.data = nullptr;
        EXPECT(verify_batch(&bp, 1) == kStatusInvalidInput, "null proof data");
        // zero proof len
        bp = good;
        bp.proof.len = 0;
        EXPECT(verify_batch(&bp, 1) == kStatusInvalidInput, "zero proof len");
        // null openings
        bp = good;
        bp.openings = nullptr;
        EXPECT(verify_batch(&bp, 1) == kStatusInvalidInput, "null openings");
        // zero openings
        bp = good;
        bp.num_openings = 0;
        EXPECT(verify_batch(&bp, 1) == kStatusInvalidInput, "zero openings");
        // y high byte 0x74 (above Banderwagon Fr ceiling)
        OpeningView bad_o[1];
        std::memset(bad_o, 0, sizeof(bad_o));
        bad_o[0].y.bytes[0] = 0x74;
        bp = good;
        bp.openings = bad_o;
        bp.num_openings = 1;
        EXPECT(verify_batch(&bp, 1) == kStatusInvalidInput, "y[0]=0x74");
        // y high byte 0xFF
        bad_o[0].y.bytes[0] = 0xFF;
        EXPECT(verify_batch(&bp, 1) == kStatusInvalidInput, "y[0]=0xFF");
        // y high byte 0x80
        bad_o[0].y.bytes[0] = 0x80;
        EXPECT(verify_batch(&bp, 1) == kStatusInvalidInput, "y[0]=0x80");
        // y high byte 0x90
        bad_o[0].y.bytes[0] = 0x90;
        EXPECT(verify_batch(&bp, 1) == kStatusInvalidInput, "y[0]=0x90");
        // y high byte 0xA0
        bad_o[0].y.bytes[0] = 0xA0;
        EXPECT(verify_batch(&bp, 1) == kStatusInvalidInput, "y[0]=0xA0");
    }

    // 10+ well-formed inputs (vary z and y_low). MUST return NOTIMPL.
    for (int i = 0; i < 12; ++i) {
        OpeningView o[2];
        std::memset(o, 0, sizeof(o));
        o[0].y.bytes[0] = uint8_t(i & 0x73);  // <= 0x73 ceiling
        o[0].y.bytes[31] = uint8_t(i);
        o[0].z = uint8_t(i * 17 % 256);
        o[1].y.bytes[0] = uint8_t((i + 7) & 0x73);
        o[1].z = uint8_t((i * 31 + 5) % 256);
        BatchProofView bp = good;
        bp.openings = o;
        bp.num_openings = 2;
        int rc = verify_batch(&bp, 1);
        EXPECT(rc == kStatusNotImplemented,
               "well-formed %d: rc=%d, want kStatusNotImplemented", i, rc);
    }

    // Mixed batch: well-formed + well-formed.
    {
        std::vector<BatchProofView> batch(3, good);
        int rc = verify_batch(batch.data(), batch.size());
        EXPECT(rc == kStatusNotImplemented, "batch=3 well-formed: rc=%d", rc);
    }

    std::printf("ipa: %d/%d passed\n", tests - failures, tests);
    return failures == 0 ? 0 : 1;
}

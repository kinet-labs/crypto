// verkle scaffold test: input-validation contract for verify_batch.

#include "verkle.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

using namespace kinet::crypto::verkle;

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
    static uint8_t fake_proof[256] = {1, 2, 3};
    static uint8_t fake_statediff[64] = {4, 5, 6};

    VerkleProofView good{};
    good.proof = fake_proof;
    good.proof_len = sizeof(fake_proof);
    good.statediff = fake_statediff;
    good.statediff_len = sizeof(fake_statediff);
    for (int i = 0; i < 32; ++i) {
        good.pre_state_root[i] = uint8_t(i);
        good.post_state_root[i] = uint8_t(i + 0x80);
    }

    // 10+ malformed
    EXPECT(verify_batch(nullptr, 1) == kStatusInvalidInput, "null proofs");
    EXPECT(verify_batch(&good, 0) == kStatusInvalidInput, "zero count");
    {
        VerkleProofView bp = good; bp.proof = nullptr;
        EXPECT(verify_batch(&bp, 1) == kStatusInvalidInput, "null proof");
    }
    {
        VerkleProofView bp = good; bp.proof_len = 0;
        EXPECT(verify_batch(&bp, 1) == kStatusInvalidInput, "zero proof_len");
    }
    {
        VerkleProofView bp = good; bp.statediff = nullptr;
        EXPECT(verify_batch(&bp, 1) == kStatusInvalidInput, "null statediff");
    }
    {
        VerkleProofView bp = good; bp.statediff_len = 0;
        EXPECT(verify_batch(&bp, 1) == kStatusInvalidInput, "zero statediff_len");
    }
    {
        // First good, second malformed
        VerkleProofView b[2] = {good, good};
        b[1].proof = nullptr;
        EXPECT(verify_batch(b, 2) == kStatusInvalidInput, "second-element null proof");
    }
    {
        // First malformed, second good
        VerkleProofView b[2] = {good, good};
        b[0].proof_len = 0;
        EXPECT(verify_batch(b, 2) == kStatusInvalidInput, "first-element zero proof_len");
    }
    {
        // Mid malformed
        VerkleProofView b[3] = {good, good, good};
        b[1].statediff = nullptr;
        EXPECT(verify_batch(b, 3) == kStatusInvalidInput, "middle null statediff");
    }
    {
        // All bad
        VerkleProofView b[4] = {good, good, good, good};
        for (int i = 0; i < 4; ++i) b[i].proof_len = 0;
        EXPECT(verify_batch(b, 4) == kStatusInvalidInput, "all bad");
    }

    // 10+ well-formed: each MUST return NOTIMPL
    for (int i = 0; i < 12; ++i) {
        std::vector<VerkleProofView> b(i + 1, good);
        // vary state roots to make each unique
        for (size_t j = 0; j < b.size(); ++j) {
            b[j].pre_state_root[0] = uint8_t(j);
            b[j].post_state_root[31] = uint8_t(j + 1);
        }
        int rc = verify_batch(b.data(), b.size());
        EXPECT(rc == kStatusNotImplemented,
               "well-formed N=%zu: rc=%d", b.size(), rc);
    }

    std::printf("verkle: %d/%d passed\n", tests - failures, tests);
    return failures == 0 ? 0 : 1;
}

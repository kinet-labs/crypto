// =============================================================================
// blake2b_full - full BLAKE2b hash on top of cevm's compression function
// =============================================================================

#include "blake2b_full.hpp"
#include "../cpp/blake2b.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace kinet::crypto::blake2b {

// IV per RFC 7693 sec 2.6 (= SHA-512 IV).
static const uint64_t IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

void hash(const uint8_t* in, size_t in_len, uint8_t out[64]) noexcept {
    constexpr size_t BLOCK = 128;
    constexpr uint32_t ROUNDS = 12;  // BLAKE2b uses 12 rounds.
    constexpr uint8_t  HASH_LEN = 64;

    // Param block sec 2.5: digest_len, key_len=0, fanout=1, depth=1.
    uint64_t h[8];
    std::memcpy(h, IV, sizeof(h));
    h[0] ^= 0x01010000ULL ^ static_cast<uint64_t>(HASH_LEN);

    // Stream input through the compress function.
    uint64_t t[2] = {0, 0};
    uint64_t m[16];
    size_t pos = 0;
    while (in_len - pos > BLOCK) {
        std::memcpy(m, in + pos, BLOCK);
        pos += BLOCK;
        t[0] += BLOCK;
        if (t[0] < BLOCK) ++t[1];
        cevm::crypto::blake2b_compress(ROUNDS, h, m, t, /*last=*/false);
    }

    // Final (possibly partial) block, zero-padded.
    std::array<uint8_t, BLOCK> last{};
    size_t rem = in_len - pos;
    if (rem) std::memcpy(last.data(), in + pos, rem);
    std::memcpy(m, last.data(), BLOCK);
    t[0] += rem;
    if (t[0] < rem) ++t[1];
    cevm::crypto::blake2b_compress(ROUNDS, h, m, t, /*last=*/true);

    // Little-endian state -> output digest.
    for (size_t i = 0; i < 8; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            out[i * 8 + j] = static_cast<uint8_t>(h[i] >> (8 * j));
        }
    }
}

}  // namespace kinet::crypto::blake2b

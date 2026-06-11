// First-party Lamport-SHA256 OTS body. The CPU implementation here is the
// canonical oracle that the Metal / CUDA / WGSL drivers must match byte-for-
// byte.

#include "lamport.hpp"
#include "sha256.hpp"

#include <cstddef>
#include <cstring>

namespace kinet::crypto::lamport
{

namespace {

inline void be32(uint8_t out[4], uint32_t v) noexcept {
    out[0] = uint8_t(v >> 24);
    out[1] = uint8_t(v >> 16);
    out[2] = uint8_t(v >>  8);
    out[3] = uint8_t(v      );
}

inline void sha256_block(uint8_t out[32], const uint8_t* in, std::size_t len) noexcept {
    cevm::crypto::sha256(reinterpret_cast<std::byte*>(out),
                         reinterpret_cast<const std::byte*>(in), len);
}

}  // namespace

void keygen(const uint8_t seed[32], uint8_t* sk, uint8_t* pk) noexcept {
    // sk slot k = sha256(seed || u32_be(k)),   k in [0, 512)
    // pk slot k = sha256(sk slot k)
    uint8_t buf[36];
    std::memcpy(buf, seed, 32);
    for (uint32_t k = 0; k < MSG_BITS * 2; ++k) {
        be32(buf + 32, k);
        sha256_block(sk + k * HASH_SIZE, buf, 36);
    }
    for (uint32_t k = 0; k < MSG_BITS * 2; ++k) {
        sha256_block(pk + k * HASH_SIZE, sk + k * HASH_SIZE, HASH_SIZE);
    }
}

void sign(const uint8_t* sk, const uint8_t msg32[32], uint8_t* sig) noexcept {
    for (std::size_t i = 0; i < MSG_BITS; ++i) {
        const uint8_t bit  = msg_bit(msg32, i);
        const std::size_t slot = i * 2 + bit;
        std::memcpy(sig + i * HASH_SIZE,
                    sk  + slot * HASH_SIZE, HASH_SIZE);
    }
}

bool verify(const uint8_t* pk, const uint8_t msg32[32], const uint8_t* sig) noexcept {
    uint8_t h[HASH_SIZE];
    for (std::size_t i = 0; i < MSG_BITS; ++i) {
        sha256_block(h, sig + i * HASH_SIZE, HASH_SIZE);
        const uint8_t bit  = msg_bit(msg32, i);
        const std::size_t slot = i * 2 + bit;
        if (std::memcmp(h, pk + slot * HASH_SIZE, HASH_SIZE) != 0) return false;
    }
    return true;
}

}  // namespace kinet::crypto::lamport

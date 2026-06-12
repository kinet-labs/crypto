// Poseidon C-ABI shim.
//
// poseidon_bn254 absorbs a sequence of 32-byte field elements through the
// t=2 Poseidon2 permutation in Merkle-Damgard mode (matches gnark-crypto's
// NewMerkleDamgardHasher) and returns a 32-byte digest.
//
// poseidon_goldilocks absorbs a sequence of 32-byte blocks (4 big-endian
// 64-bit Goldilocks lanes per block) through the t=8 Poseidon2 permutation
// in Merkle-Damgard mode (all-zero IV, 8-lane state, 4 lanes absorbed per
// step into the top half of the state) and returns the top 4 lanes (32
// bytes) as the digest. Algorithm + constants match horizen-labs/poseidon2:
//   plain_implementations/src/poseidon2/poseidon2_instance_goldilocks.rs
// (POSEIDON2_GOLDILOCKS_8_PARAMS) byte-for-byte. KAT vectors generated from
// the upstream Rust crate live in test/poseidon_goldilocks_test.cpp.

#include "crypto.h"
#include "../cpp/poseidon.hpp"
#include "../cpp/fr_bn254.hpp"
#include "../cpp/poseidon_goldilocks.hpp"
#include "../cpp/goldilocks.hpp"

#include <cstring>

extern "C" int poseidon_goldilocks(const uint8_t* in, size_t in_len, uint8_t out[32]) {
    if (out == nullptr) return CRYPTO_ERR_INPUT;
    if (in_len > 0 && in == nullptr) return CRYPTO_ERR_INPUT;
    // Block size is 4 lanes * 8 bytes = 32 bytes (the public absorb width;
    // matches the digest width). The internal state is 8 lanes — absorbed
    // input fills the top 4 lanes, the bottom 4 lanes act as capacity.
    if (in_len % 32 != 0) return CRYPTO_ERR_LENGTH;

    using namespace kinet::crypto::poseidon;

    uint64_t state[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    const size_t blocks = in_len / 32;

    for (size_t b = 0; b < blocks; ++b) {
        uint64_t lanes[4];
        for (int i = 0; i < 4; ++i) {
            if (!p2g::bytes_to_lane_canonical(in + b * 32 + i * 8, lanes[i])) {
                return CRYPTO_ERR_INPUT;
            }
        }
        // Absorb into top half of state (state[0..3]). Bottom half is capacity.
        for (int i = 0; i < 4; ++i) {
            state[i] = gf::add(state[i], lanes[i]);
        }
        p2g::permutation_t8(state);
    }

    // Squeeze: emit top 4 lanes as 32-byte big-endian digest.
    for (int i = 0; i < 4; ++i) {
        p2g::lane_to_bytes(state[i], out + i * 8);
    }
    return CRYPTO_OK;
}

extern "C" int poseidon_bn254(const uint8_t* in, size_t in_len, uint8_t out[32]) {
    if (out == nullptr) return CRYPTO_ERR_INPUT;
    if (in_len > 0 && in == nullptr) return CRYPTO_ERR_INPUT;
    if (in_len % 32 != 0) return CRYPTO_ERR_LENGTH;

    // gnark-crypto's NewMerkleDamgardHasher uses an all-zero IV and feeds
    // each 32-byte block as the right input to Compress(left=state, right=in).
    // Compress applies the t=2 permutation in place and returns
    // permuted_state[1] + original_right.
    uint8_t state[32] = {0};
    for (size_t i = 0; i < in_len; i += 32) {
        uint8_t left[32];  std::memcpy(left,  state, 32);
        uint8_t right[32]; std::memcpy(right, in + i, 32);
        uint8_t saved_right[32]; std::memcpy(saved_right, right, 32);
        if (!kinet::crypto::poseidon::permutation_t2(left, right)) {
            return CRYPTO_ERR_INPUT;
        }
        // state[1] + saved_right (gnark-crypto Compress contract).
        // Mod-r addition over the result (`right` after permutation) and the
        // original right input.
        uint64_t r1[4], r0[4];
        if (!kinet::crypto::poseidon::fr::from_bytes_be(r1, right))       return CRYPTO_ERR_INPUT;
        if (!kinet::crypto::poseidon::fr::from_bytes_be(r0, saved_right)) return CRYPTO_ERR_INPUT;
        uint64_t out_state[4];
        kinet::crypto::poseidon::fr::add_mod(out_state, r1, r0);
        kinet::crypto::poseidon::fr::to_bytes_be(state, out_state);
    }

    std::memcpy(out, state, 32);
    return CRYPTO_OK;
}

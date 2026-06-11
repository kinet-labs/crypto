// Poseidon C-ABI shim.
//
// poseidon_bn254 absorbs a sequence of 32-byte field elements through the
// t=2 Poseidon2 permutation in Merkle-Damgard mode (matches gnark-crypto's
// NewMerkleDamgardHasher) and returns a 32-byte digest.
//
// poseidon_goldilocks remains NOTIMPL until the Goldilocks variant lands.

#include "kinet_crypto.h"
#include "../cpp/poseidon.hpp"

#include <cstring>

extern "C" int poseidon_goldilocks(const uint8_t*, size_t, uint8_t[32]) {
    return CRYPTO_ERR_NOTIMPL;
}

extern "C" int poseidon_bn254(const uint8_t* in, size_t in_len, uint8_t out[32]) {
    if (out == nullptr) return CRYPTO_ERR_INPUT;
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

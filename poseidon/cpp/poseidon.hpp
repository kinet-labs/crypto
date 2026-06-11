// First-party Poseidon2 over the BN254 scalar field (Fr).
//
// Parameters: t=2, rF=8 (rounds split 6 full = 3 pre + 3 post... wait, the
// canonical default for gnark-crypto is rF=6, rP=50, d=5). This is the same
// permutation used by gnark-crypto's NewMerkleDamgardHasher.
//
// Round constants are derived deterministically by the gnark-crypto initRC
// path (Keccak-256 chain seeded with the parameter string
// "Poseidon2-BN254[t=2,rF=6,rP=50,d=5]"). They are baked into
// poseidon_constants.cpp as 256-bit hex literals.

#pragma once
#include <array>
#include <cstdint>

namespace kinet::crypto::poseidon {

constexpr int    P2_WIDTH          = 2;
constexpr int    P2_FULL_ROUNDS    = 6;
constexpr int    P2_PARTIAL_ROUNDS = 50;
constexpr int    P2_SBOX_DEGREE    = 5;
constexpr size_t P2_FE_BYTES       = 32;

// 256-bit BN254 scalar field element, big-endian byte layout (matches
// gnark-crypto's fr.Element.Marshal()). Internally we operate on Montgomery
// 4-limb little-endian representation.
struct Fr {
    uint64_t limbs[4];  // Montgomery form, little-endian limbs
};

// Apply the t=2 Poseidon2 permutation in-place to `state` (two field
// elements). `state` is read and overwritten with the permutation output.
//
// Inputs and outputs are 32-byte big-endian canonical field elements
// (matches gnark-crypto's fr.Element.Marshal()/SetBytesCanonical()).
//
// Returns false if either input byte sequence is not in canonical form
// (>= the BN254 modulus); true on success.
bool permutation_t2(uint8_t left[P2_FE_BYTES], uint8_t right[P2_FE_BYTES]) noexcept;

}  // namespace kinet::crypto::poseidon

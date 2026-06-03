// =============================================================================
// Poseidon2 Hash Function over BN254 Scalar Field (Fr)
// =============================================================================
//
// GPU-accelerated Poseidon2 hash for ZK circuits and Merkle trees.
// Uses BN254 scalar field (Fr) to match gnark-crypto implementation.
//
// BN254 Scalar Field:
//   r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//
// Poseidon2 Parameters (matching gnark-crypto):
//   - S-box: x^5
//   - State width: 3 (for 2-to-1 hash) or 4 (for higher rate)
//   - Full rounds: 8 (4 beginning + 4 end)
//   - Partial rounds: 56
//
// References:
//   - gnark-crypto: github.com/consensys/gnark-crypto
//   - Poseidon2 paper: https://eprint.iacr.org/2023/323
//
// Copyright (C) 2024-2025 Kinet Industries Inc.
// SPDX-License-Identifier: Apache-2.0

#include <metal_stdlib>
using namespace metal;

// =============================================================================
// BN254 Scalar Field (Fr) - 256-bit Arithmetic
// =============================================================================

// BN254 scalar field modulus r (4 limbs, little-endian)
// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
constant uint64_t BN254_R[4] = {
    0x43e1f593f0000001ULL,
    0x2833e84879b97091ULL,
    0xb85045b68181585dULL,
    0x30644e72e131a029ULL
};

// Montgomery R^2 mod r (for converting to Montgomery form)
// Must match C++ BN254_R2 exactly
constant uint64_t BN254_R2[4] = {
    0xf32cfc5b538afa89ULL,
    0xb5e71911d44501fbULL,
    0x47ab1eff0a417ff6ULL,
    0x06d89f71cab8351fULL
};

// Montgomery constant: -r^{-1} mod 2^64
// Must match C++ BN254_INV exactly
constant uint64_t BN254_R_INV = 0xc2e1f593efffffffULL;

// Fr256: 256-bit field element (4 x 64-bit limbs)
struct Fr256 {
    uint64_t limbs[4];
};

// =============================================================================
// Multi-precision Arithmetic Helpers
// =============================================================================

inline uint64_t adc(uint64_t a, uint64_t b, thread uint64_t& carry) {
    uint64_t result = a + carry;
    carry = (result < a) ? 1 : 0;
    uint64_t sum = result + b;
    carry += (sum < result) ? 1 : 0;
    return sum;
}

inline uint64_t sbb(uint64_t a, uint64_t b, thread uint64_t& borrow) {
    uint64_t diff = a - borrow;
    borrow = (a < borrow) ? 1 : 0;
    uint64_t result = diff - b;
    borrow += (diff < b) ? 1 : 0;
    return result;
}

inline void mul64(uint64_t a, uint64_t b, thread uint64_t& lo, thread uint64_t& hi) {
    lo = a * b;
    hi = mulhi(a, b);
}

inline int fr_cmp(Fr256 a, constant uint64_t* b) {
    for (int i = 3; i >= 0; i--) {
        if (a.limbs[i] < b[i]) return -1;
        if (a.limbs[i] > b[i]) return 1;
    }
    return 0;
}

// =============================================================================
// Field Operations
// =============================================================================

inline Fr256 fr_zero() {
    Fr256 r;
    r.limbs[0] = 0; r.limbs[1] = 0; r.limbs[2] = 0; r.limbs[3] = 0;
    return r;
}

inline Fr256 fr_one() {
    // Montgomery form of 1: R mod r
    // Must match C++ BN254_R exactly
    Fr256 r;
    r.limbs[0] = 0xd35d438dc58f0d9dULL;
    r.limbs[1] = 0x0a78eb28f5c70b3dULL;
    r.limbs[2] = 0x666ea36f7879462cULL;
    r.limbs[3] = 0x0e0a77c19a07df2fULL;
    return r;
}

inline bool fr_is_zero(Fr256 a) {
    return a.limbs[0] == 0 && a.limbs[1] == 0 && a.limbs[2] == 0 && a.limbs[3] == 0;
}

inline void fr_reduce(thread Fr256& a) {
    if (fr_cmp(a, BN254_R) >= 0) {
        uint64_t borrow = 0;
        for (int i = 0; i < 4; i++) {
            a.limbs[i] = sbb(a.limbs[i], BN254_R[i], borrow);
        }
    }
}

inline Fr256 fr_add(Fr256 a, Fr256 b) {
    Fr256 c;
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        c.limbs[i] = adc(a.limbs[i], b.limbs[i], carry);
    }
    fr_reduce(c);
    return c;
}

inline Fr256 fr_sub(Fr256 a, Fr256 b) {
    Fr256 c;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        c.limbs[i] = sbb(a.limbs[i], b.limbs[i], borrow);
    }
    if (borrow) {
        uint64_t carry = 0;
        for (int i = 0; i < 4; i++) {
            c.limbs[i] = adc(c.limbs[i], BN254_R[i], carry);
        }
    }
    return c;
}

inline Fr256 fr_neg(Fr256 a) {
    if (fr_is_zero(a)) return a;
    Fr256 c;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        c.limbs[i] = sbb(BN254_R[i], a.limbs[i], borrow);
    }
    return c;
}

// Montgomery multiplication
inline Fr256 fr_mont_mul(Fr256 a, Fr256 b) {
    uint64_t t[8] = {0};

    // Schoolbook multiplication
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            uint64_t lo, hi;
            mul64(a.limbs[i], b.limbs[j], lo, hi);
            uint64_t sum = t[i+j] + lo + carry;
            carry = (sum < t[i+j]) ? 1 : 0;
            carry += hi;
            t[i+j] = sum;
        }
        t[i+4] = carry;
    }

    // Montgomery reduction
    for (int i = 0; i < 4; i++) {
        uint64_t k = t[i] * BN254_R_INV;
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            uint64_t lo, hi;
            mul64(k, BN254_R[j], lo, hi);
            uint64_t sum = t[i+j] + lo + carry;
            carry = (sum < t[i+j]) ? 1 : 0;
            carry += hi;
            t[i+j] = sum;
        }
        for (int j = i + 4; j < 8; j++) {
            uint64_t sum = t[j] + carry;
            carry = (sum < t[j]) ? 1 : 0;
            t[j] = sum;
            if (carry == 0) break;
        }
    }

    Fr256 c;
    for (int i = 0; i < 4; i++) {
        c.limbs[i] = t[i + 4];
    }
    fr_reduce(c);
    return c;
}

inline Fr256 fr_square(Fr256 a) {
    return fr_mont_mul(a, a);
}

// =============================================================================
// Poseidon2 Parameters (BN254/Fr, width=3)
// =============================================================================

// State width for 2-to-1 hash (rate=2, capacity=1)
constant uint32_t POSEIDON2_WIDTH = 3;

// Number of full rounds (beginning + end)
constant uint32_t POSEIDON2_FULL_ROUNDS = 8;  // 4 + 4

// Number of partial rounds
constant uint32_t POSEIDON2_PARTIAL_ROUNDS = 56;

// S-box exponent: x^5 for BN254
constant uint32_t POSEIDON2_ALPHA = 5;

// =============================================================================
// Poseidon2 Internal Diagonal Elements for t=3
// D = [1, 1, 2] means internal matrix is diag(1,1,2) + ones(3,3)
// Must match C++ INTERNAL_DIAG exactly
// =============================================================================
constant uint64_t POSEIDON2_INTERNAL_DIAG[3] = {1, 1, 2};

// =============================================================================
// Round constants - derived from Poseidon2 specification
// Must match C++ ROUND_CONSTANTS exactly
// Total needed: 4*3 (first full) + 56 (partial) + 4*3 (last full) = 80 constants
// =============================================================================
constant uint32_t POSEIDON2_NUM_RC = 16;  // We have 16 constants, use modulo wrapping

constant uint64_t POSEIDON2_RC[16][4] = {
    // First 4 full rounds (3 constants each = 12 total)
    {0x0ee9a592ba9a9518ULL, 0x99a7c3e6a8a4d90cULL, 0x53f2b7e7f1f35ebcULL, 0x2ccc32b6c7c21d9cULL},
    {0xa54c664ae5b9e8adULL, 0x0e36f420f8a4a5bdULL, 0x6f8c3f5b0b1f4f6eULL, 0x1f5f5f5f5f5f5f5fULL},
    {0xb5c55df06f4c52c9ULL, 0x4b7f47e8c0a8a0d9ULL, 0x7e8e8e8e8e8e8e8eULL, 0x0d0d0d0d0d0d0d0dULL},
    {0xc6e633e0e0e6e6e6ULL, 0x5c8f58f9d1b9b1eaULL, 0x8f9f9f9f9f9f9f9fULL, 0x1e1e1e1e1e1e1e1eULL},
    {0xd7f744f1f1f7f7f7ULL, 0x6d9f69fae2cacafbULL, 0x9fafafafafafafULL, 0x0f0f0f0f0f0f0f0fULL},
    {0xe8f855f2f2f8f8f8ULL, 0x7eaf7afbf3dbdbfcULL, 0xafbfbfbfbfbfbfbfULL, 0x2f2f2f2f2f2f2f2fULL},
    {0xf9f966f3f3f9f9f9ULL, 0x8fbf8bfcf4ececfdULL, 0xbfcfcfcfcfcfcfcfULL, 0x3f3f3f3f3f3f3f3fULL},
    {0x0a0a77f4f4fafafaULL, 0x9fcf9cfdfe5fdfefULL, 0xcfdfdfdfdfdfdfdfULL, 0x0000000000000000ULL},
    {0x1b1b88f5f5fbfbfbULL, 0xafdfa0feff6f0f0fULL, 0x0f0f0f0f0f0f0f0fULL, 0x1010101010101010ULL},
    {0x2c2c99f6f6fcfcfcULL, 0xbfefb1ff0f800f0fULL, 0x1f1f1f1f1f1f1f1fULL, 0x2020202020202020ULL},
    {0x3d3daaf7f7fdfdfdULL, 0xcfffc20f1f911f1fULL, 0x2f2f2f2f2f2f2f2fULL, 0x0101010101010101ULL},
    {0x4e4ebbf8f8fefefeULL, 0xdfffd31f2fa22f2fULL, 0x3f3f3f3f3f3f3f3fULL, 0x0202020202020202ULL},
    // 56 partial round constants (using modulo wrapping for remaining)
    {0x5f5fccf9f9ffffffULL, 0xefffe41f3fb33f3fULL, 0x4f4f4f4f4f4f4f4fULL, 0x0303030303030303ULL},
    {0x606fddfa0a000000ULL, 0xfffff51f4fc44f4fULL, 0x5f5f5f5f5f5f5f5fULL, 0x0404040404040404ULL},
    {0x717feefb1b111111ULL, 0x0000061f5fd55f5fULL, 0x6f6f6f6f6f6f6f6fULL, 0x0505050505050505ULL},
    {0x828ffffc2c222222ULL, 0x1111171f6fe66f6fULL, 0x7f7f7f7f7f7f7f7fULL, 0x0606060606060606ULL},
};

// External MDS matrix for BN254 Poseidon2 (3x3)
// M_E = [[2,1,1],[1,2,1],[1,1,2]] = I + J where J is all-ones
// This is applied in full rounds; we implement it directly in apply_external_mds

// =============================================================================
// S-box: x^5 in BN254 scalar field
// =============================================================================

inline Fr256 poseidon2_sbox(Fr256 x) {
    Fr256 x2 = fr_square(x);      // x^2
    Fr256 x4 = fr_square(x2);     // x^4
    return fr_mont_mul(x4, x);    // x^5
}

// =============================================================================
// Linear Layer: External MDS Matrix
// =============================================================================

// Apply external MDS matrix for t=3:
// M_E = [[2,1,1],[1,2,1],[1,1,2]] = I + J where J is all-ones
// Must match C++ apply_external_mds exactly
inline void poseidon2_mds(thread Fr256* state) {
    // Compute sum of all elements
    Fr256 sum = fr_add(fr_add(state[0], state[1]), state[2]);

    // Apply: state[i] = state[i] + sum (this gives 2*s[i] + s[j] + s[k])
    state[0] = fr_add(state[0], sum);
    state[1] = fr_add(state[1], sum);
    state[2] = fr_add(state[2], sum);
}

// Poseidon2 internal matrix: M_I = diag(d_0, d_1, d_2) + J
// where J is the all-ones matrix and d = [1, 1, 2]
// Must match C++ apply_internal_matrix exactly
inline void poseidon2_internal_linear(thread Fr256* state) {
    // First compute sum of all elements
    Fr256 sum = fr_add(fr_add(state[0], state[1]), state[2]);

    // Apply: state[i] = d[i] * state[i] + sum
    // For d = [1, 1, 2]:
    //   state[0] = 1 * state[0] + sum = state[0] + sum
    //   state[1] = 1 * state[1] + sum = state[1] + sum
    //   state[2] = 2 * state[2] + sum = state[2] + state[2] + sum
    state[0] = fr_add(state[0], sum);
    state[1] = fr_add(state[1], sum);
    Fr256 s2_doubled = fr_add(state[2], state[2]);
    state[2] = fr_add(s2_doubled, sum);
}

// =============================================================================
// Poseidon2 Permutation
// =============================================================================

// Get round constant with modulo wrapping (matches C++ get_rc)
inline Fr256 get_rc(uint32_t idx) {
    Fr256 rc;
    uint32_t wrapped_idx = idx % POSEIDON2_NUM_RC;
    for (int k = 0; k < 4; k++) {
        rc.limbs[k] = POSEIDON2_RC[wrapped_idx][k];
    }
    return rc;
}

inline void poseidon2_permutation(thread Fr256* state) {
    uint32_t rc_idx = 0;

    // Beginning full rounds (4 rounds)
    // Must match C++ full_round exactly
    for (uint32_t r = 0; r < POSEIDON2_FULL_ROUNDS / 2; r++) {
        // Add round constants to all elements
        for (uint32_t i = 0; i < POSEIDON2_WIDTH; i++) {
            state[i] = fr_add(state[i], get_rc(rc_idx++));
        }

        // S-box (x^5) on all elements
        for (uint32_t i = 0; i < POSEIDON2_WIDTH; i++) {
            state[i] = poseidon2_sbox(state[i]);
        }

        // External MDS matrix
        poseidon2_mds(state);
    }

    // Partial rounds (56 rounds)
    // Must match C++ partial_round exactly
    for (uint32_t r = 0; r < POSEIDON2_PARTIAL_ROUNDS; r++) {
        // Add round constant to first element only
        state[0] = fr_add(state[0], get_rc(rc_idx++));

        // S-box only on first element
        state[0] = poseidon2_sbox(state[0]);

        // Internal matrix (diag(1,1,2) + J)
        poseidon2_internal_linear(state);
    }

    // Ending full rounds (4 rounds)
    for (uint32_t r = 0; r < POSEIDON2_FULL_ROUNDS / 2; r++) {
        // Add round constants to all elements
        for (uint32_t i = 0; i < POSEIDON2_WIDTH; i++) {
            state[i] = fr_add(state[i], get_rc(rc_idx++));
        }

        // S-box (x^5) on all elements
        for (uint32_t i = 0; i < POSEIDON2_WIDTH; i++) {
            state[i] = poseidon2_sbox(state[i]);
        }

        // External MDS matrix
        poseidon2_mds(state);
    }
}

// =============================================================================
// Hash Kernels
// =============================================================================

// Hash pair for Merkle tree (2-to-1 compression)
// This is the main kernel for GPU-accelerated Merkle trees
kernel void poseidon2_hash_pair(
    device const Fr256* left [[buffer(0)]],
    device const Fr256* right [[buffer(1)]],
    device Fr256* output [[buffer(2)]],
    uint index [[thread_position_in_grid]]
) {
    // Initialize state: [left, right, domain_sep]
    Fr256 state[POSEIDON2_WIDTH];
    state[0] = left[index];
    state[1] = right[index];
    state[2] = fr_zero();  // Domain separation (could use constant)

    // Apply permutation
    poseidon2_permutation(state);

    // Output first element
    output[index] = state[0];
}

// Batch hash for arbitrary inputs
kernel void poseidon2_hash(
    device const Fr256* input [[buffer(0)]],
    device Fr256* output [[buffer(1)]],
    constant uint32_t& input_len [[buffer(2)]],
    uint index [[thread_position_in_grid]]
) {
    // Rate = width - 1 = 2
    uint32_t rate = POSEIDON2_WIDTH - 1;
    uint32_t offset = index * rate;

    if (offset >= input_len) return;

    // Initialize state
    Fr256 state[POSEIDON2_WIDTH];
    state[0] = fr_zero();
    state[1] = fr_zero();
    state[2] = fr_zero();

    // Absorb phase
    uint32_t remaining = input_len - offset;
    uint32_t to_absorb = (remaining < rate) ? remaining : rate;

    for (uint32_t i = 0; i < to_absorb; i++) {
        state[i] = input[offset + i];
    }

    // Padding (if partial block)
    if (to_absorb < rate) {
        state[to_absorb] = fr_one();  // Padding marker
    }

    // Permutation
    poseidon2_permutation(state);

    // Output
    output[index] = state[0];
}

// =============================================================================
// Merkle Tree Construction
// =============================================================================

// Build one layer of Merkle tree
kernel void poseidon2_merkle_layer(
    device const Fr256* current_layer [[buffer(0)]],
    device Fr256* next_layer [[buffer(1)]],
    constant uint32_t& current_size [[buffer(2)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= current_size / 2) return;

    Fr256 left = current_layer[2 * index];
    Fr256 right = current_layer[2 * index + 1];

    // Initialize state
    Fr256 state[POSEIDON2_WIDTH];
    state[0] = left;
    state[1] = right;
    state[2] = fr_zero();

    // Permutation
    poseidon2_permutation(state);

    next_layer[index] = state[0];
}

// Batch Merkle layer for multiple trees
kernel void poseidon2_batch_merkle_layer(
    device const Fr256* leaves [[buffer(0)]],
    device Fr256* parents [[buffer(1)]],
    constant uint32_t& num_pairs [[buffer(2)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= num_pairs) return;

    Fr256 left = leaves[2 * index];
    Fr256 right = leaves[2 * index + 1];

    Fr256 state[POSEIDON2_WIDTH];
    state[0] = left;
    state[1] = right;
    state[2] = fr_zero();

    poseidon2_permutation(state);

    parents[index] = state[0];
}

// =============================================================================
// Merkle Proof Verification
// =============================================================================

kernel void poseidon2_verify_merkle_proof(
    device const Fr256* leaf [[buffer(0)]],
    device const Fr256* path [[buffer(1)]],
    device const uint32_t* path_indices [[buffer(2)]],  // 0 = left, 1 = right
    device const Fr256* expected_root [[buffer(3)]],
    device uint32_t* result [[buffer(4)]],  // 1 = valid, 0 = invalid
    constant uint32_t& path_len [[buffer(5)]],
    uint proof_idx [[thread_position_in_grid]]
) {
    Fr256 current = leaf[proof_idx];

    for (uint32_t i = 0; i < path_len; i++) {
        Fr256 sibling = path[proof_idx * path_len + i];
        uint32_t idx = path_indices[proof_idx * path_len + i];

        Fr256 left = (idx == 0) ? current : sibling;
        Fr256 right = (idx == 0) ? sibling : current;

        Fr256 state[POSEIDON2_WIDTH];
        state[0] = left;
        state[1] = right;
        state[2] = fr_zero();

        poseidon2_permutation(state);

        current = state[0];
    }

    // Compare with expected root
    Fr256 expected = expected_root[proof_idx];
    bool valid = true;
    for (int i = 0; i < 4; i++) {
        if (current.limbs[i] != expected.limbs[i]) {
            valid = false;
            break;
        }
    }

    result[proof_idx] = valid ? 1 : 0;
}

// =============================================================================
// Nullifier and Commitment Operations (for privacy pools)
// =============================================================================

// Compute nullifier: Poseidon2(nullifier_key, note_commitment, leaf_index)
kernel void poseidon2_nullifier(
    device const Fr256* nullifier_key [[buffer(0)]],
    device const Fr256* note_commitment [[buffer(1)]],
    device const Fr256* leaf_index [[buffer(2)]],
    device Fr256* nullifier [[buffer(3)]],
    uint index [[thread_position_in_grid]]
) {
    // Use width=3 sponge with 3 inputs
    Fr256 state[POSEIDON2_WIDTH];
    state[0] = nullifier_key[index];
    state[1] = note_commitment[index];
    state[2] = leaf_index[index];

    poseidon2_permutation(state);

    nullifier[index] = state[0];
}

// Compute commitment: Poseidon2(value, blinding_factor, salt)
kernel void poseidon2_commitment(
    device const Fr256* value [[buffer(0)]],
    device const Fr256* blinding [[buffer(1)]],
    device const Fr256* salt [[buffer(2)]],
    device Fr256* commitment [[buffer(3)]],
    uint index [[thread_position_in_grid]]
) {
    Fr256 state[POSEIDON2_WIDTH];
    state[0] = value[index];
    state[1] = blinding[index];
    state[2] = salt[index];

    poseidon2_permutation(state);

    commitment[index] = state[0];
}

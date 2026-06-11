// First-party Poseidon2 over BN254 scalar field, t=2 default parameters.
// Matches gnark-crypto v0.20.1 NewMerkleDamgardHasher() permutation byte-for
// -byte (verified against KAT vectors generated from gnark-crypto directly).
//
// Algorithm (eprint 2023/323, page 15 case t=2):
//   - matMulExternal: state = M_E * state with M_E = [[2,1],[1,2]].
//     Implemented as `tmp = state[0] + state[1]; state[0] += tmp; state[1] += tmp;`.
//   - matMulInternal: state = M_I * state with M_I = [[2,1],[1,3]].
//     Implemented as `sum = state[0] + state[1]; state[0] += sum; state[1] = 2*state[1] + sum;`.
//   - sBox: x -> x^5.
//
// Round structure: matMulExternal → 3 full rounds (sBox both lanes) → 50
// partial rounds (sBox lane 0 only) → 3 full rounds. Each round prepends
// "addRoundKey".

#include "poseidon.hpp"
#include "fr_bn254.hpp"
#include "poseidon_constants.hpp"

#include <array>
#include <cstring>

namespace kinet::crypto::poseidon {

namespace {

using fr::add_mod;
using fr::pow5_mod;
using fr::double_mod;

// Round-key cache: parsed once on first use.
struct RoundKeys {
    uint64_t full_pre[3][2][4];   // 3 rounds * 2 lanes * 4 limbs
    uint64_t partial[50][4];
    uint64_t full_post[3][2][4];
    bool     loaded;
};

static RoundKeys& keys() noexcept {
    static RoundKeys k = {};
    if (!k.loaded) {
        for (int i = 0; i < 3; ++i) {
            (void)fr::from_hex_be(k.full_pre[i][0], p2_t2::RC_FULL_PRE[i][0]);
            (void)fr::from_hex_be(k.full_pre[i][1], p2_t2::RC_FULL_PRE[i][1]);
        }
        for (int i = 0; i < 50; ++i) {
            (void)fr::from_hex_be(k.partial[i], p2_t2::RC_PARTIAL[i]);
        }
        for (int i = 0; i < 3; ++i) {
            (void)fr::from_hex_be(k.full_post[i][0], p2_t2::RC_FULL_POST[i][0]);
            (void)fr::from_hex_be(k.full_post[i][1], p2_t2::RC_FULL_POST[i][1]);
        }
        k.loaded = true;
    }
    return k;
}

// External matrix [[2,1],[1,2]] times state.
inline void mat_external(uint64_t s0[4], uint64_t s1[4]) noexcept {
    uint64_t tmp[4];
    add_mod(tmp, s0, s1);
    uint64_t old_s0[4]; std::memcpy(old_s0, s0, sizeof(old_s0));
    add_mod(s0, tmp, old_s0);
    uint64_t old_s1[4]; std::memcpy(old_s1, s1, sizeof(old_s1));
    add_mod(s1, tmp, old_s1);
}

// Internal matrix [[2,1],[1,3]] times state, equivalently:
//   sum = s0 + s1;
//   s0  = s0 + sum   = 2*s0 + s1
//   s1  = 2*s1 + sum = s0 + 3*s1
inline void mat_internal(uint64_t s0[4], uint64_t s1[4]) noexcept {
    uint64_t sum[4];
    add_mod(sum, s0, s1);
    uint64_t old_s0[4]; std::memcpy(old_s0, s0, sizeof(old_s0));
    add_mod(s0, old_s0, sum);
    uint64_t two_s1[4];
    double_mod(two_s1, s1);
    add_mod(s1, two_s1, sum);
}

inline void add_rk_full(uint64_t s0[4], uint64_t s1[4],
                        const uint64_t k0[4], const uint64_t k1[4]) noexcept {
    uint64_t tmp0[4], tmp1[4];
    add_mod(tmp0, s0, k0);
    add_mod(tmp1, s1, k1);
    std::memcpy(s0, tmp0, sizeof(tmp0));
    std::memcpy(s1, tmp1, sizeof(tmp1));
}

inline void add_rk_partial(uint64_t s0[4], const uint64_t k0[4]) noexcept {
    uint64_t tmp[4];
    add_mod(tmp, s0, k0);
    std::memcpy(s0, tmp, sizeof(tmp));
}

inline void sbox(uint64_t s[4]) noexcept {
    uint64_t tmp[4];
    pow5_mod(tmp, s);
    std::memcpy(s, tmp, sizeof(tmp));
}

}  // namespace

bool permutation_t2(uint8_t left[P2_FE_BYTES], uint8_t right[P2_FE_BYTES]) noexcept {
    uint64_t s0[4], s1[4];
    if (!fr::from_bytes_be(s0, left))  return false;
    if (!fr::from_bytes_be(s1, right)) return false;

    const RoundKeys& k = keys();

    // Initial external matrix.
    mat_external(s0, s1);

    // Pre-full rounds (3): full sbox + external matrix.
    for (int i = 0; i < 3; ++i) {
        add_rk_full(s0, s1, k.full_pre[i][0], k.full_pre[i][1]);
        sbox(s0);
        sbox(s1);
        mat_external(s0, s1);
    }

    // Partial rounds (50): sbox lane 0 only + internal matrix.
    for (int i = 0; i < 50; ++i) {
        add_rk_partial(s0, k.partial[i]);
        sbox(s0);
        mat_internal(s0, s1);
    }

    // Post-full rounds (3): full sbox + external matrix.
    for (int i = 0; i < 3; ++i) {
        add_rk_full(s0, s1, k.full_post[i][0], k.full_post[i][1]);
        sbox(s0);
        sbox(s1);
        mat_external(s0, s1);
    }

    fr::to_bytes_be(left,  s0);
    fr::to_bytes_be(right, s1);
    return true;
}

}  // namespace kinet::crypto::poseidon

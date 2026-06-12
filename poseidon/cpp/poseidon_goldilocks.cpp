// First-party Poseidon2-Goldilocks-t=8 permutation. Byte-equal to
// horizen-labs/poseidon2 @ main / poseidon2_instance_goldilocks.rs
// (POSEIDON2_GOLDILOCKS_8_PARAMS) — verified against 18 KAT vectors generated
// from the upstream Rust crate (see test/poseidon_goldilocks_test.cpp).

#include "poseidon_goldilocks.hpp"
#include "poseidon_goldilocks_constants.hpp"
#include "goldilocks.hpp"

#include <cstring>

namespace kinet::crypto::poseidon::p2g {

namespace {

using gf::add;
using gf::dbl;
using gf::pow7;
using gf::mul;
using gf::canon;

// matmul_m4: cheap 4x4 MDS matrix on a 4-lane block, identical to
// horizen-labs/poseidon2 poseidon2.rs::matmul_m4. Operates in place.
inline void matmul_m4(uint64_t* x) noexcept {
    uint64_t t0 = add(x[0], x[1]);
    uint64_t t1 = add(x[2], x[3]);
    uint64_t t2 = add(dbl(x[1]), t1);
    uint64_t t3 = add(dbl(x[3]), t0);
    uint64_t t4 = add(dbl(dbl(t1)), t3);
    uint64_t t5 = add(dbl(dbl(t0)), t2);
    uint64_t t6 = add(t3, t5);
    uint64_t t7 = add(t2, t4);
    x[0] = t6;
    x[1] = t5;
    x[2] = t7;
    x[3] = t4;
}

// External matrix for t=8: apply M4 to each 4-lane block, then add the
// per-position sum (across blocks) of the same lane.
//   stored[l] = sum over j of state[4*j + l]
//   state[i] += stored[i % 4]
inline void mat_external_t8(uint64_t s[8]) noexcept {
    matmul_m4(s);
    matmul_m4(s + 4);

    uint64_t stored[4];
    for (int l = 0; l < 4; ++l) {
        stored[l] = add(s[l], s[l + 4]);
    }
    for (int i = 0; i < 8; ++i) {
        s[i] = add(s[i], stored[i & 3]);
    }
}

// Internal matrix for t=8:
//   sum = state[0] + state[1] + ... + state[7]
//   state[i] = state[i] * (MAT_DIAG[i] + 1) - state[i] + sum
//            = state[i] * MAT_DIAG[i] + sum    where MAT_DIAG = (diag - 1)
// matches upstream's "mul_assign(diag_m_1); add_assign(sum)" loop after the
// implicit "mul by (diag_m_1 + 1)" rewrite — but upstream actually multiplies
// by the *full* diagonal (the values stored in MAT_DIAG8_M_1 are the diagonal
// entries minus 1, so the loop is:
//   acc = state[i] * mat_diag_m_1[i]   // = state[i] * (diag - 1) = state[i]*diag - state[i]
//   state[i] = acc + sum
// which equals state[i]*diag + (sum - state[i])  — *not* the same as
// sum-includes-state[i]; this is exactly what upstream does.
inline void mat_internal_t8(uint64_t s[8]) noexcept {
    uint64_t sum = s[0];
    for (int i = 1; i < 8; ++i) sum = add(sum, s[i]);
    for (int i = 0; i < 8; ++i) {
        // s[i] = s[i] * MAT_DIAG[i] + sum
        // (MAT_DIAG[i] is the upstream "diag - 1" coefficient).
        s[i] = add(mul(s[i], MAT_DIAG8_M_1[i]), sum);
    }
}

inline void add_rc_full(uint64_t s[8], const uint64_t rc[8]) noexcept {
    for (int i = 0; i < 8; ++i) s[i] = add(s[i], rc[i]);
}

inline void sbox_full(uint64_t s[8]) noexcept {
    for (int i = 0; i < 8; ++i) s[i] = pow7(s[i]);
}

}  // namespace

void permutation_t8(uint64_t state[8]) noexcept {
    // Initial linear layer.
    mat_external_t8(state);

    // Pre-full rounds: rounds 0..HALF_FULL (=4).
    for (int r = 0; r < HALF_FULL; ++r) {
        add_rc_full(state, RC8[r]);
        sbox_full(state);
        mat_external_t8(state);
    }

    // Partial rounds: rounds HALF_FULL..HALF_FULL+PARTIAL_ROUNDS.
    for (int r = HALF_FULL; r < HALF_FULL + PARTIAL_ROUNDS; ++r) {
        state[0] = add(state[0], RC8[r][0]);
        state[0] = pow7(state[0]);
        mat_internal_t8(state);
    }

    // Post-full rounds.
    for (int r = HALF_FULL + PARTIAL_ROUNDS; r < TOTAL_ROUNDS; ++r) {
        add_rc_full(state, RC8[r]);
        sbox_full(state);
        mat_external_t8(state);
    }
}

void merkle_damgard_t8(const uint64_t* in_lanes,
                       size_t          in_lanes_len,
                       uint64_t        out_state[8]) noexcept {
    uint64_t s[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (size_t i = 0; i < in_lanes_len; i += 8) {
        for (int j = 0; j < 8; ++j) {
            s[j] = add(s[j], canon(in_lanes[i + j]));
        }
        permutation_t8(s);
    }
    std::memcpy(out_state, s, sizeof(s));
}

bool bytes_to_lane_canonical(const uint8_t in[8], uint64_t& out) noexcept {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | (uint64_t)in[i];
    }
    if (v >= gf::MOD) return false;
    out = v;
    return true;
}

void lane_to_bytes(uint64_t in, uint8_t out[8]) noexcept {
    for (int i = 7; i >= 0; --i) {
        out[i] = (uint8_t)(in & 0xFFu);
        in >>= 8;
    }
}

}  // namespace kinet::crypto::poseidon::p2g

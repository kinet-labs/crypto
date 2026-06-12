// Poseidon2 over the Goldilocks field (p = 2^64 - 2^32 + 1).
// Width t=8, sBox x^7, full rounds 8 (4 pre + 4 post), partial rounds 22.
//
// Algorithm (Grassi-Khovratovich-Rechberger eprint 2023/323) as instantiated
// in horizen-labs/poseidon2 @ main / poseidon2_instance_goldilocks.rs:
//
//   matMulExternal(state)
//   for r in 0..rF/2:
//       state[i] += RC[r][i]                  (full add-round-key)
//       state[i]  = state[i]^7                (full sBox)
//       matMulExternal(state)
//   for r in rF/2..rF/2+rP:
//       state[0] += RC[r][0]                  (partial add-round-key)
//       state[0]  = state[0]^7                (partial sBox, lane 0 only)
//       matMulInternal(state, MAT_DIAG8_M_1)
//   for r in rF/2+rP..rF+rP:
//       state[i] += RC[r][i]                  (full add-round-key)
//       state[i]  = state[i]^7                (full sBox)
//       matMulExternal(state)
//
// matMulExternal for t=8 = (M4 block) ⊕ (second cheap matrix) — see eprint
// 2023/323 §5.1 and the upstream reference.
//
// Hash mode: Merkle-Damgard with all-zero IV. Each absorb step ingests t
// field elements (8 * 8 bytes = 64 bytes per block, big-endian per-lane), adds
// the absorbed elements into the running state, then applies the permutation.
// Output is the full state (8 lanes) serialized big-endian = 64 bytes; the
// public C-ABI emits the first 4 lanes (32 bytes) as the digest.

#pragma once
#include <cstdint>
#include <cstddef>

namespace kinet::crypto::poseidon::p2g {

inline constexpr size_t LANE_BYTES   = 8;          // 64-bit Goldilocks lane
inline constexpr size_t STATE_BYTES  = LANE_BYTES * 8;     // 64 bytes
inline constexpr size_t DIGEST_BYTES = LANE_BYTES * 4;     // 32 bytes (top half)

// Apply the t=8 Poseidon2 permutation in place to `state`. All 8 lanes must
// already be canonical (in [0, p)).
void permutation_t8(uint64_t state[8]) noexcept;

// Merkle-Damgard hash. `in_lanes_len` must be a multiple of 8 (one block = 8
// lanes). Inputs that are not canonical (>= p) are reduced modulo p before
// absorption — they correspond to non-canonical big-endian byte encodings, so
// the C-ABI rejects them at parse time before calling this function.
//
// `out_state` receives the full 8-lane state after the final permutation.
void merkle_damgard_t8(const uint64_t* in_lanes,
                       size_t          in_lanes_len,
                       uint64_t        out_state[8]) noexcept;

// Big-endian 8-byte conversion helpers. `bytes_to_lane_canonical` returns
// false iff the encoded value is >= p (non-canonical).
bool bytes_to_lane_canonical(const uint8_t in[8], uint64_t& out) noexcept;
void lane_to_bytes(uint64_t in, uint8_t out[8]) noexcept;

}  // namespace kinet::crypto::poseidon::p2g

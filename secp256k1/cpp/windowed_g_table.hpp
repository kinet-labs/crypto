// Windowed precomputation of multiples of G for fast u1*G in ecrecover.
//
// We use a fixed window width w = 4 across CPU, Metal, CUDA and WGSL so that
// every backend produces byte-identical Q1 = u1*G. No GLV (saved for v0.64
// behind a feature flag); no NAF; no signed-digit recoding -- canonical only.
//
// Layout: 64 windows of 16 entries (w=4 -> 16 multiples per window).
//
//   table[wi][k] = (k * 2^(4*wi)) * G       for wi in [0, 64), k in [0, 16)
//
// Total: 64 * 16 = 1024 affine points. With Fp in Montgomery form (32 bytes
// per coordinate), the table is 1024 * 64 = 65,536 bytes.
//
// Scalar mult algorithm: split scalar k into 64 nibbles k_0..k_63 (LSB first).
//   Q = sum_i  table[i][k_i]
// All 64 mixed additions, no doublings -- the doublings are baked into the
// table.

#pragma once

#include "field.hpp"
#include "curve.hpp"

#include <array>
#include <cstdint>

namespace kinet::crypto::secp256k1 {

constexpr int WINDOW_BITS    = 4;
constexpr int WINDOW_SIZE    = 1 << WINDOW_BITS; // 16
constexpr int NUM_WINDOWS    = 256 / WINDOW_BITS; // 64
constexpr int TABLE_ENTRIES  = NUM_WINDOWS * WINDOW_SIZE; // 1024

struct WindowedGTable {
    // Affine x and y coordinates in Montgomery form, plus an "infinity" flag
    // for entry [wi][0] (which is always the identity).
    AffinePoint entries[TABLE_ENTRIES];
};

// Build the table using the existing scalar mult routine. Computed once at
// library init; threadsafe to read after init.
inline WindowedGTable build_windowed_g_table() noexcept {
    WindowedGTable t;

    // Affine generator in Montgomery form.
    AffinePoint G;
    G.x = to_mont_p(GX);
    G.y = to_mont_p(GY);
    G.infinity = false;

    // For each window position wi, compute base_wi = 2^(4*wi) * G via
    // repeated doubling. Then table[wi][k] = k * base_wi for k in [0, 16).
    JacobianPoint base_j = affine_to_jacobian(G);
    for (int wi = 0; wi < NUM_WINDOWS; ++wi) {
        // table[wi][0] = identity
        t.entries[wi * WINDOW_SIZE + 0].x = U256{};
        t.entries[wi * WINDOW_SIZE + 0].y = U256{};
        t.entries[wi * WINDOW_SIZE + 0].infinity = true;

        // table[wi][1] = base_wi (in affine, for mixed-add)
        AffinePoint base_aff = jacobian_to_affine(base_j);
        t.entries[wi * WINDOW_SIZE + 1] = base_aff;

        // table[wi][k] = k * base_wi for k = 2..15
        JacobianPoint acc = base_j;
        for (int k = 2; k < WINDOW_SIZE; ++k) {
            acc = jac_add_mixed(acc, base_aff);
            t.entries[wi * WINDOW_SIZE + k] = jacobian_to_affine(acc);
        }

        // Advance base_j by w = 4 doublings to reach 2^(4*(wi+1)) * G.
        for (int i = 0; i < WINDOW_BITS; ++i) base_j = jac_double(base_j);
    }
    return t;
}

// Scalar mult using the windowed table: Q = k * G.
// k is in plain (non-Montgomery) form; k.limbs[0] is least significant.
inline JacobianPoint scalar_mul_g_windowed(const WindowedGTable& t, const U256& k) noexcept {
    JacobianPoint acc = jac_zero();
    for (int wi = 0; wi < NUM_WINDOWS; ++wi) {
        // Extract nibble: limb = wi/16, nibble offset = (wi%16)*4
        int limb = wi / 16;
        int shift = (wi % 16) * 4;
        unsigned nib = (unsigned)((k.limbs[limb] >> shift) & 0xFu);
        if (nib == 0) continue;
        acc = jac_add_mixed(acc, t.entries[wi * WINDOW_SIZE + nib]);
    }
    return acc;
}

// Singleton accessor. The table is built lazily on first call.
inline const WindowedGTable& windowed_g_table() noexcept {
    static const WindowedGTable t = build_windowed_g_table();
    return t;
}

}  // namespace kinet::crypto::secp256k1

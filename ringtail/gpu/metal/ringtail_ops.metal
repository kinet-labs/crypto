// Copyright (c) 2024-2026 Kinet Partners Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Ringtail Lattice Threshold Operations - Metal Implementation
// Post-quantum threshold signatures based on Module-LWE (MLWE).

#include <metal_stdlib>
using namespace metal;

// ============================================================================
// Ringtail Parameters (Dilithium-like construction)
// ============================================================================

constant uint Q = 8380417;             // Modulus 2^23 - 2^13 + 1
constant uint N = 256;                 // Ring dimension
constant uint K = 4;                   // Module rank for public key
constant uint L = 4;                   // Module rank for secret
constant int GAMMA1 = 131072;          // Commitment bound (2^17)
constant int GAMMA2 = 95232;           // Low bits rounding
constant uint QINV = 58728449;         // q^-1 mod 2^32

// ============================================================================
// Modular Arithmetic
// ============================================================================

inline int mont_reduce(long a) {
    int t = int(uint(a) * QINV);
    return int((a - long(t) * Q) >> 32);
}

inline int mod_add(int a, int b) {
    int r = a + b;
    if (r >= int(Q)) r -= Q;
    if (r < 0) r += Q;
    return r;
}

inline int mod_sub(int a, int b) {
    int r = a - b;
    if (r < 0) r += Q;
    return r;
}

inline int caddq(int a) {
    return a + ((a >> 31) & int(Q));
}

inline int freeze(int a) {
    a = caddq(a);
    return a - int(Q) + ((int(Q) - 1 - a) >> 31 & int(Q));
}

// ============================================================================
// Polynomial Structures
// ============================================================================

struct Poly {
    int coeffs[256];
};

struct PolyVec {
    Poly polys[4];  // L polynomials
};

struct ThresholdShare {
    uint index;
    PolyVec s_share;
    PolyVec y_share;
};

// ============================================================================
// High/Low Bits Decomposition
// ============================================================================

inline int highbits(int r, int alpha) {
    r = freeze(r);
    int r1 = (r + (alpha >> 1)) / alpha;
    return r1;
}

inline int lowbits(int r, int alpha) {
    int r1 = highbits(r, alpha);
    return r - r1 * alpha;
}

// ============================================================================
// Lagrange Interpolation
// ============================================================================

// Compute modular inverse using extended Euclidean algorithm
inline int mod_inv_int(int a, uint q) {
    int t = 0, new_t = 1;
    int r = int(q), new_r = a;

    while (new_r != 0) {
        int quotient = r / new_r;
        int temp_t = t - quotient * new_t;
        t = new_t;
        new_t = temp_t;

        int temp_r = r - quotient * new_r;
        r = new_r;
        new_r = temp_r;
    }

    if (t < 0) t += int(q);
    return t;
}

// Compute Lagrange coefficient at x=0
inline int compute_lagrange_coeff(
    uint index,
    device const uint* indices,
    uint num_shares
) {
    long numerator = 1;
    long denominator = 1;

    for (uint j = 0; j < num_shares; j++) {
        if (indices[j] == index) continue;

        numerator = (numerator * long(indices[j])) % Q;
        long diff = long(indices[j]) - long(index);
        if (diff < 0) diff += Q;
        denominator = (denominator * diff) % Q;
    }

    int inv = mod_inv_int(int(denominator), Q);
    return int((numerator * inv) % Q);
}

// ============================================================================
// Share Combination Kernel
// ============================================================================

kernel void combine_shares(
    device const int* shares_s [[buffer(0)]],    // [num_shares][L][N]
    device const int* shares_y [[buffer(1)]],    // [num_shares][L][N]
    device const uint* share_indices [[buffer(2)]],
    device const uint* participant_indices [[buffer(3)]],
    device int* combined_s [[buffer(4)]],        // [L][N]
    device int* combined_y [[buffer(5)]],        // [L][N]
    constant uint& num_shares [[buffer(6)]],
    uint2 gid [[thread_position_in_grid]]        // (coeff_idx, poly_idx)
) {
    uint coeff_idx = gid.x;
    uint poly_idx = gid.y;

    if (coeff_idx >= N || poly_idx >= L) return;

    long s_sum = 0;
    long y_sum = 0;

    for (uint i = 0; i < num_shares; i++) {
        int lambda = compute_lagrange_coeff(participant_indices[i], participant_indices, num_shares);

        uint offset = i * L * N + poly_idx * N + coeff_idx;
        long s_val = shares_s[offset];
        long y_val = shares_y[offset];

        s_sum = (s_sum + (s_val * lambda) % Q + Q) % Q;
        y_sum = (y_sum + (y_val * lambda) % Q + Q) % Q;
    }

    uint out_offset = poly_idx * N + coeff_idx;
    combined_s[out_offset] = int(s_sum);
    combined_y[out_offset] = int(y_sum);
}

// ============================================================================
// Commitment Computation (A*y in NTT domain)
// ============================================================================

kernel void compute_commitment(
    device const int* A [[buffer(0)]],           // [K][L][N] in NTT domain
    device const int* y [[buffer(1)]],           // [L][N]
    device int* w [[buffer(2)]],                 // [K][N]
    uint2 gid [[thread_position_in_grid]]        // (coeff_idx, row)
) {
    uint coeff_idx = gid.x;
    uint row = gid.y;

    if (coeff_idx >= N || row >= K) return;

    long sum = 0;

    for (uint col = 0; col < L; col++) {
        int a_val = A[row * L * N + col * N + coeff_idx];
        int y_val = y[col * N + coeff_idx];
        long prod = long(a_val) * y_val;
        sum += mont_reduce(prod);
    }

    w[row * N + coeff_idx] = freeze(int(sum % Q));
}

// ============================================================================
// Response Bounds Check
// ============================================================================

kernel void check_response_bounds(
    device const int* z [[buffer(0)]],           // [L][N]
    device atomic_uint* valid [[buffer(1)]],
    constant int& gamma1_minus_beta [[buffer(2)]],
    uint2 gid [[thread_position_in_grid]]
) {
    uint coeff_idx = gid.x;
    uint poly_idx = gid.y;

    if (coeff_idx >= N || poly_idx >= L) return;

    int val = z[poly_idx * N + coeff_idx];
    val = freeze(val);

    // Check |z| < gamma1 - beta
    if (val > gamma1_minus_beta && val < int(Q) - gamma1_minus_beta) {
        atomic_store_explicit(valid, 0u, memory_order_relaxed);
    }
}

// ============================================================================
// Hint Generation
// ============================================================================

kernel void make_hint(
    device const int* r [[buffer(0)]],           // [K][N]
    device const int* z [[buffer(1)]],           // [K][N]
    device uchar* hint [[buffer(2)]],            // [K][N]
    device atomic_uint* hint_count [[buffer(3)]],
    uint2 gid [[thread_position_in_grid]]
) {
    uint coeff_idx = gid.x;
    uint poly_idx = gid.y;

    if (coeff_idx >= N || poly_idx >= K) return;

    uint idx = poly_idx * N + coeff_idx;

    int r_val = r[idx];
    int z_val = z[idx];

    int r_high = highbits(r_val, 2 * GAMMA2);
    int rz_high = highbits(mod_add(r_val, z_val), 2 * GAMMA2);

    if (r_high != rz_high) {
        hint[idx] = 1;
        atomic_fetch_add_explicit(hint_count, 1u, memory_order_relaxed);
    } else {
        hint[idx] = 0;
    }
}

// ============================================================================
// Use Hint for Verification
// ============================================================================

kernel void use_hint(
    device const int* r0 [[buffer(0)]],
    device const int* r1 [[buffer(1)]],
    device const uchar* hint [[buffer(2)]],
    device int* recovered [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= K * N) return;

    int r0_val = r0[gid];
    int r1_val = r1[gid];
    uchar h = hint[gid];

    if (h == 0) {
        recovered[gid] = r1_val;
    } else {
        int max_high = (int(Q) - 1) / (2 * GAMMA2) + 1;
        if (r0_val > 0) {
            recovered[gid] = (r1_val + 1) % max_high;
        } else {
            recovered[gid] = (r1_val + max_high - 1) % max_high;
        }
    }
}

// ============================================================================
// Batch Share Combination
// ============================================================================

kernel void batch_combine_shares(
    device const int* all_shares_s [[buffer(0)]],    // [batch][num_shares][L][N]
    device const int* all_shares_y [[buffer(1)]],
    device const uint* all_indices [[buffer(2)]],    // [batch][num_shares]
    device int* combined_s [[buffer(3)]],            // [batch][L][N]
    device int* combined_y [[buffer(4)]],
    constant uint& num_shares [[buffer(5)]],
    constant uint& batch_size [[buffer(6)]],
    uint3 gid [[thread_position_in_grid]]            // (coeff, poly, batch)
) {
    uint coeff_idx = gid.x;
    uint poly_idx = gid.y;
    uint batch_idx = gid.z;

    if (coeff_idx >= N || poly_idx >= L || batch_idx >= batch_size) return;

    device const uint* indices = all_indices + batch_idx * num_shares;

    long s_sum = 0;
    long y_sum = 0;

    for (uint i = 0; i < num_shares; i++) {
        int lambda = compute_lagrange_coeff(indices[i], indices, num_shares);

        uint offset = batch_idx * num_shares * L * N + i * L * N + poly_idx * N + coeff_idx;
        long s_val = all_shares_s[offset];
        long y_val = all_shares_y[offset];

        s_sum = (s_sum + (s_val * lambda) % Q + Q) % Q;
        y_sum = (y_sum + (y_val * lambda) % Q + Q) % Q;
    }

    uint out_offset = batch_idx * L * N + poly_idx * N + coeff_idx;
    combined_s[out_offset] = int(s_sum);
    combined_y[out_offset] = int(y_sum);
}

// ============================================================================
// Power2Round Decomposition
// ============================================================================

kernel void power2round(
    device const int* r [[buffer(0)]],
    device int* r1 [[buffer(1)]],
    device int* r0 [[buffer(2)]],
    constant uint& d [[buffer(3)]],
    constant uint& n [[buffer(4)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= n) return;

    int val = r[gid];
    int half = 1 << (d - 1);

    r1[gid] = (val + half - 1) >> d;
    r0[gid] = val - (r1[gid] << d);
}

// ============================================================================
// Polynomial Sampling with Bounded Coefficients
// ============================================================================

// Simple hash-based random for sampling
inline uint pcg_hash(uint input) {
    uint state = input * 747796405u + 2891336453u;
    uint word = ((state >> ((state >> 28u) + 4u)) ^ state) * 277803737u;
    return (word >> 22u) ^ word;
}

kernel void sample_poly_eta(
    device int* poly [[buffer(0)]],
    constant uint& seed [[buffer(1)]],
    constant uint& eta [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= N) return;

    uint rng = pcg_hash(seed ^ gid);
    int sample = int(rng % (2 * eta + 1)) - int(eta);
    poly[gid] = sample;
}

kernel void sample_poly_gamma1(
    device int* poly [[buffer(0)]],
    constant uint& seed [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= N) return;

    uint rng = pcg_hash(seed ^ gid);
    int r = int(rng % (2 * uint(GAMMA1) + 1));
    poly[gid] = GAMMA1 - r;
}

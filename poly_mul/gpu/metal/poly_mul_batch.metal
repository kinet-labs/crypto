// Copyright (C) 2020-2026, Kinet Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Metal kernel for batched polynomial multiplication over Q = 998244353.
// Byte-equal to kinet-labs/crypto/poly_mul.MulSchoolbook for n <= 1024.
//
// Threading: one thread per (batch_idx, output_coefficient_idx). Each thread
// computes c[k] = sum_{i+j=k} a[i]*b[j] - sum_{i+j=k+n} a[i]*b[j] for one k
// independently of every other coefficient. n is bounded by NMAX (1024) to
// fit per-thread accumulation into a single uint64.

#include <metal_stdlib>
using namespace metal;

constant uint64_t Q_PRIME = 998244353UL;
constant uint NMAX = 1024;

inline uint64_t add_mod(uint64_t a, uint64_t b) {
    uint64_t s = a + b;
    if (s >= Q_PRIME) s -= Q_PRIME;
    return s;
}

inline uint64_t sub_mod(uint64_t a, uint64_t b) {
    return a >= b ? a - b : a + Q_PRIME - b;
}

inline uint64_t mul_mod(uint64_t a, uint64_t b) {
    // Q < 2^30 so a*b < 2^60 -- fits a uint64 with no overflow before reduction.
    return (a * b) % Q_PRIME;
}

// Each thread computes one coefficient c[k] of one batch element.
// gid.x = output coefficient index k (0..n-1)
// gid.y = batch index
kernel void poly_mul_schoolbook_batch(
    device const uint64_t* a       [[buffer(0)]],   // [batch_size * n]
    device const uint64_t* b       [[buffer(1)]],   // [batch_size * n]
    device       uint64_t* c       [[buffer(2)]],   // [batch_size * n]
    constant uint& n               [[buffer(3)]],
    constant uint& batch_size      [[buffer(4)]],
    uint2 gid                      [[thread_position_in_grid]])
{
    if (gid.x >= n || gid.y >= batch_size) return;
    if (n > NMAX) return;

    uint k = gid.x;
    uint base = gid.y * n;

    uint64_t sum = 0;

    // Positive terms: i+j == k
    for (uint i = 0; i <= k; ++i) {
        uint j = k - i;
        uint64_t prod = mul_mod(a[base + i] % Q_PRIME, b[base + j] % Q_PRIME);
        sum = add_mod(sum, prod);
    }
    // Negative terms (negacyclic wrap): i+j == k+n
    for (uint i = k + 1; i < n; ++i) {
        uint j = (k + n) - i;
        uint64_t prod = mul_mod(a[base + i] % Q_PRIME, b[base + j] % Q_PRIME);
        sum = sub_mod(sum, prod);
    }

    c[base + k] = sum;
}

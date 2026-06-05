// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// CPU LSD radix sort -- 8-bit pass over each byte. Stable.
//
// Allocates n elements of scratch on the stack via std::vector. The sort is
// straightforward; this function defines the byte-equal target for GPU radix
// sort kernels.

#include "kinet/gpukit/radix_sort.h"
#include <vector>
#include <cstring>

namespace {

template <typename T>
void radix_sort_lsd(T* keys, size_t n) {
    if (n < 2) return;
    std::vector<T> tmp(n);
    constexpr int RADIX_BITS = 8;
    constexpr int RADIX = 1 << RADIX_BITS;
    constexpr int PASSES = static_cast<int>(sizeof(T));

    T* src = keys;
    T* dst = tmp.data();
    for (int pass = 0; pass < PASSES; ++pass) {
        size_t cnt[RADIX];
        std::memset(cnt, 0, sizeof(cnt));
        const int shift = pass * RADIX_BITS;
        for (size_t i = 0; i < n; ++i) {
            cnt[(src[i] >> shift) & (RADIX - 1)] += 1;
        }
        // Exclusive scan to get destination offsets.
        size_t acc = 0;
        for (int b = 0; b < RADIX; ++b) {
            size_t c = cnt[b];
            cnt[b] = acc;
            acc += c;
        }
        // Stable scatter.
        for (size_t i = 0; i < n; ++i) {
            uint8_t b = static_cast<uint8_t>((src[i] >> shift) & (RADIX - 1));
            dst[cnt[b]++] = src[i];
        }
        T* swap = src; src = dst; dst = swap;
    }
    if (src != keys) {
        std::memcpy(keys, src, n * sizeof(T));
    }
}

}  // namespace

extern "C" void gpukit_radix_sort_u32_cpu(uint32_t* keys, size_t n) {
    radix_sort_lsd<uint32_t>(keys, n);
}

extern "C" void gpukit_radix_sort_u64_cpu(uint64_t* keys, size_t n) {
    radix_sort_lsd<uint64_t>(keys, n);
}

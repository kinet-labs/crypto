/* Copyright (c) 2024-2026 Kinet Industries Inc.
 * SPDX-License-Identifier: BSD-3-Clause-Eco
 *
 * Stable LSD radix sort over u32/u64 keys. Ascending order.
 *
 * Caller supplies an aux buffer of the same length as the input; the sorted
 * result lands in `out` (which may equal `in`).
 */
#ifndef KINET_GPUKIT_RADIX_SORT_H
#define KINET_GPUKIT_RADIX_SORT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void gpukit_radix_sort_u32_cpu(uint32_t* keys, size_t n);
void gpukit_radix_sort_u64_cpu(uint64_t* keys, size_t n);

int gpukit_radix_sort_u32_metal(uint32_t* keys, size_t n);
int gpukit_radix_sort_u64_metal(uint64_t* keys, size_t n);

int gpukit_radix_sort_u32_cuda(uint32_t* keys, size_t n);
int gpukit_radix_sort_u64_cuda(uint64_t* keys, size_t n);

int gpukit_radix_sort_u32_wgsl(uint32_t* keys, size_t n);
int gpukit_radix_sort_u64_wgsl(uint64_t* keys, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* KINET_GPUKIT_RADIX_SORT_H */

/* Copyright (c) 2024-2026 Kinet Industries Inc.
 * SPDX-License-Identifier: BSD-3-Clause-Eco
 *
 * Stream compaction. Stable -- preserves the original index order of selected
 * elements. Returns the number of selected elements (n_out).
 */
#ifndef KINET_GPUKIT_COMPACTION_H
#define KINET_GPUKIT_COMPACTION_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* in/out can be u32 values; flags[i] != 0 selects in[i]. */
size_t gpukit_compact_u32_cpu(const uint32_t* in, const uint8_t* flags,
                              uint32_t* out, size_t n);

int gpukit_compact_u32_metal(const uint32_t* in, const uint8_t* flags,
                             uint32_t* out, size_t n, size_t* n_out);
int gpukit_compact_u32_cuda(const uint32_t* in, const uint8_t* flags,
                            uint32_t* out, size_t n, size_t* n_out);
int gpukit_compact_u32_wgsl(const uint32_t* in, const uint8_t* flags,
                            uint32_t* out, size_t n, size_t* n_out);

#ifdef __cplusplus
}
#endif

#endif /* KINET_GPUKIT_COMPACTION_H */

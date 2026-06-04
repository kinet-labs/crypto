/*
 * Inclusive prefix sum (scan).
 *   out[0] = in[0]
 *   out[i] = out[i-1] + in[i]
 * No overflow handling -- caller chooses the integer width that fits the sum.
 */
#ifndef KINET_GPUKIT_PREFIX_SUM_H
#define KINET_GPUKIT_PREFIX_SUM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CPU reference -- always available, defines the byte-equal target. */
void gpukit_prefix_sum_u32_cpu(const uint32_t* in, uint32_t* out, size_t n);
void gpukit_prefix_sum_u64_cpu(const uint64_t* in, uint64_t* out, size_t n);

/* Metal backend (returns -3 if not built; -4 on dispatch failure). */
int gpukit_prefix_sum_u32_metal(const uint32_t* in, uint32_t* out, size_t n);
int gpukit_prefix_sum_u64_metal(const uint64_t* in, uint64_t* out, size_t n);

/* CUDA backend. */
int gpukit_prefix_sum_u32_cuda(const uint32_t* in, uint32_t* out, size_t n);
int gpukit_prefix_sum_u64_cuda(const uint64_t* in, uint64_t* out, size_t n);

/* WGSL backend (Dawn / wgpu-native). */
int gpukit_prefix_sum_u32_wgsl(const uint32_t* in, uint32_t* out, size_t n);
int gpukit_prefix_sum_u64_wgsl(const uint64_t* in, uint64_t* out, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* KINET_GPUKIT_PREFIX_SUM_H */

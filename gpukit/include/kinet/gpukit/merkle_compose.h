/* Copyright (c) 2024-2026 Kinet Industries Inc.
 * SPDX-License-Identifier: BSD-3-Clause-Eco
 *
 * Parallel binary Merkle tree with Keccak-256 inner hash.
 *
 * Layout:
 *   * Leaves are 32-byte values, consumed in input order.
 *   * Tree is zero-padded to the next power of two with the all-zero leaf.
 *   * Inner node = keccak256( left || right )  (concat, big-endian byte stream).
 *
 * gpukit_merkle_root computes only the 32-byte root.
 * gpukit_merkle_layers writes each layer (leaves first, root last) to `layers`.
 *
 *   layers buffer size = (2 * pow2(n) - 1) * 32  bytes
 *   pow2(n) = smallest power of two >= n (>=1)
 */
#ifndef KINET_GPUKIT_MERKLE_COMPOSE_H
#define KINET_GPUKIT_MERKLE_COMPOSE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void gpukit_merkle_root_cpu(const uint8_t* leaves, size_t n, uint8_t out_root[32]);

int gpukit_merkle_root_metal(const uint8_t* leaves, size_t n, uint8_t out_root[32]);
int gpukit_merkle_root_cuda(const uint8_t* leaves, size_t n, uint8_t out_root[32]);
int gpukit_merkle_root_wgsl(const uint8_t* leaves, size_t n, uint8_t out_root[32]);

#ifdef __cplusplus
}
#endif

#endif /* KINET_GPUKIT_MERKLE_COMPOSE_H */

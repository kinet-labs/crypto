/* Copyright (c) 2024-2026 Kinet Industries Inc.
 * SPDX-License-Identifier: BSD-3-Clause-Eco
 *
 * Canonical proof artifact emitted by every GPU primitive that participates in
 * the expand_inputs / parallel_eval / reduce / commit_root pipeline. Quasar and
 * higher-level proof systems consume this uniformly.
 */
#ifndef KINET_GPUKIT_PROOF_RESULT_H
#define KINET_GPUKIT_PROOF_RESULT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gpukit_proof_result {
    uint8_t  input_root[32];
    uint8_t  output_root[32];
    uint8_t  transcript_root[32];
    uint32_t count;
    uint32_t failed_count;
    uint32_t flags;
} gpukit_proof_result;

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* KINET_GPUKIT_PROOF_RESULT_H */

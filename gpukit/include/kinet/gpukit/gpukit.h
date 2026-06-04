/*
 * gpukit -- common GPU kernel-pattern library.
 *
 * Every primitive follows expand_inputs / parallel_eval / reduce / commit_root.
 * Backends are selected via the GPUKIT_BACKEND environment variable:
 *   "cpu"  -- portable C++ reference (always available)
 *   "metal"-- Apple Metal (Apple silicon / macOS / iOS)
 *   "cuda" -- NVIDIA CUDA (Linux + CUDA build)
 *   "wgsl" -- Dawn / wgpu-native via WebGPU C API
 *
 * All callable surfaces are brand-neutral. Symbols start with `gpukit_`. The
 * `kinet/` path scope is the only place the brand appears.
 */
#ifndef KINET_GPUKIT_GPUKIT_H
#define KINET_GPUKIT_GPUKIT_H

#include "kinet/gpukit/proof_result.h"
#include "kinet/gpukit/prefix_sum.h"
#include "kinet/gpukit/compaction.h"
#include "kinet/gpukit/radix_sort.h"
#include "kinet/gpukit/batch_inversion.h"
#include "kinet/gpukit/merkle_compose.h"
#include "kinet/gpukit/transcript_root.h"
#include "kinet/gpukit/ntt.h"
#include "kinet/gpukit/arena.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Backend selection. NULL or empty -> read GPUKIT_BACKEND env var. */
typedef enum gpukit_backend {
    GPUKIT_BACKEND_CPU   = 0,
    GPUKIT_BACKEND_METAL = 1,
    GPUKIT_BACKEND_CUDA  = 2,
    GPUKIT_BACKEND_WGSL  = 3,
} gpukit_backend;

/* Status codes shared by all primitives. */
typedef enum gpukit_status {
    GPUKIT_OK             = 0,
    GPUKIT_ERR_NULL_ARG   = -1,
    GPUKIT_ERR_BAD_SIZE   = -2,
    GPUKIT_ERR_BACKEND    = -3,
    GPUKIT_ERR_DISPATCH   = -4,
    GPUKIT_ERR_NOTIMPL    = -5,
    GPUKIT_ERR_DETERMINISM = -6,
} gpukit_status;

/* Resolve the active backend by reading GPUKIT_BACKEND. Defaults to CPU. */
gpukit_backend gpukit_active_backend(void);

/* Library version (semver-encoded: major*10000 + minor*100 + patch). */
uint32_t gpukit_version(void);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* KINET_GPUKIT_GPUKIT_H */

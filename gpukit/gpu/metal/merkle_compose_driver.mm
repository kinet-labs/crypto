// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Metal merkle_compose driver -- v1.1 ships CPU only. Parallel Keccak-256
// inner hashing is part of the keccak Stage 2 GPU port (sibling agent owns
// the per-leaf parallel Keccak kernel). When that lands, this driver fans out
// the leaves into a Keccak-256-batch dispatch, then walks the tree on GPU.

#if __APPLE__ && __OBJC__

#include "kinet/gpukit/merkle_compose.h"
#include "kinet/gpukit/gpukit.h"

extern "C" int gpukit_merkle_root_metal(const uint8_t*, size_t, uint8_t[32]) {
    return GPUKIT_ERR_NOTIMPL;
}

#endif // __APPLE__ && __OBJC__

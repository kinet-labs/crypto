// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "kinet/gpukit/compaction.h"
#include "kinet/gpukit/gpukit.h"

extern "C" int gpukit_compact_u32_wgsl(const uint32_t*, const uint8_t*, uint32_t*, size_t, size_t*) {
    return GPUKIT_ERR_NOTIMPL;
}

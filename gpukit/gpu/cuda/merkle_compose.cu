// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
// v1.1: NOTIMPL.

#include "kinet/gpukit/merkle_compose.h"
#include "kinet/gpukit/gpukit.h"

extern "C" int gpukit_merkle_root_cuda(const uint8_t*, size_t, uint8_t[32]) {
    return GPUKIT_ERR_NOTIMPL;
}

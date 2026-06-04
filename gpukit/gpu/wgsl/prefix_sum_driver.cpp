// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// WGSL prefix_sum driver.
//
// v1.1 of gpukit ships the WGSL shader source files but does not yet wire up
// the wgpu-native runtime host integration. The shader files validate as
// standalone WGSL and will plug into the v1.2 runtime driver. Until then the
// callable surface returns NOTIMPL so the harness skips Metal/CUDA-equivalent
// dispatch on this primitive when GPUKIT_BACKEND=wgsl.

#include "kinet/gpukit/prefix_sum.h"
#include "kinet/gpukit/gpukit.h"

extern "C" int gpukit_prefix_sum_u32_wgsl(const uint32_t*, uint32_t*, size_t) {
    return GPUKIT_ERR_NOTIMPL;
}
extern "C" int gpukit_prefix_sum_u64_wgsl(const uint64_t*, uint64_t*, size_t) {
    return GPUKIT_ERR_NOTIMPL;
}

// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Metal transcript_root driver -- v1.1 ships CPU only. Keccak sponge is
// inherently serial within a single transcript; the GPU win comes from
// processing multiple transcripts in parallel. That batch entry point is
// scoped to v1.2 alongside the keccak GPU port.

#if __APPLE__ && __OBJC__

#include "kinet/gpukit/transcript_root.h"
#include "kinet/gpukit/gpukit.h"

extern "C" int gpukit_transcript_root_metal(const char*, const uint8_t*, size_t, uint8_t[32]) {
    return GPUKIT_ERR_NOTIMPL;
}

#endif // __APPLE__ && __OBJC__

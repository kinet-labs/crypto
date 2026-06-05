// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Metal NTT driver -- v1.1 ships CPU only. Forward and inverse NTT on Metal
// is straightforward (radix-2 butterfly with bit-reversed roots) but pinning
// it byte-equal across Apple's tile schedulers requires a deterministic warp
// order which is the v1.2 work. For now we honestly return NOTIMPL so the
// caller can fall back to CPU.

#if __APPLE__ && __OBJC__

#include "kinet/gpukit/ntt.h"
#include "kinet/gpukit/gpukit.h"

extern "C" int gpukit_ntt_kyber_forward_metal(int32_t*, size_t) { return GPUKIT_ERR_NOTIMPL; }
extern "C" int gpukit_ntt_kyber_negacyclic_mul_metal(const int32_t*, const int32_t*, int32_t*, size_t) {
    return GPUKIT_ERR_NOTIMPL;
}
extern "C" int gpukit_ntt_dilithium_forward_metal(int32_t*, size_t) { return GPUKIT_ERR_NOTIMPL; }

#endif // __APPLE__ && __OBJC__

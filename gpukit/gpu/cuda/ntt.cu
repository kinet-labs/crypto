// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
// v1.1: NOTIMPL. Forward / negacyclic-mul kernels for Kyber and Dilithium are
// scheduled for v1.2.

#include "kinet/gpukit/ntt.h"
#include "kinet/gpukit/gpukit.h"

extern "C" int gpukit_ntt_kyber_forward_cuda(int32_t*, size_t) { return GPUKIT_ERR_NOTIMPL; }
extern "C" int gpukit_ntt_kyber_negacyclic_mul_cuda(const int32_t*, const int32_t*, int32_t*, size_t) {
    return GPUKIT_ERR_NOTIMPL;
}
extern "C" int gpukit_ntt_dilithium_forward_cuda(int32_t*, size_t) { return GPUKIT_ERR_NOTIMPL; }

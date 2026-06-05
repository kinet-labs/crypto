// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "kinet/gpukit/batch_inversion.h"
#include "kinet/gpukit/gpukit.h"

extern "C" int gpukit_batch_inv_secp256k1_fp_wgsl(const uint8_t*, uint8_t*, size_t) { return GPUKIT_ERR_NOTIMPL; }
extern "C" int gpukit_batch_inv_bn254_fp_wgsl(const uint8_t*, uint8_t*, size_t)     { return GPUKIT_ERR_NOTIMPL; }
extern "C" int gpukit_batch_inv_bls12_381_fp_wgsl(const uint8_t*, uint8_t*, size_t) { return GPUKIT_ERR_NOTIMPL; }

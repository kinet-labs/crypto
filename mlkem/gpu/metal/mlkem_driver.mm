// =============================================================================
// Metal ML-KEM - GPU Acceleration for Post-Quantum Key Encapsulation
// =============================================================================
//
// Implementation of ML-KEM (FIPS 203) with Metal GPU acceleration.
// Falls back to CPU implementation when GPU is not available.
//
// Copyright (C) 2024-2025 Kinet Industries Inc.
// SPDX-License-Identifier: Apache-2.0

#include "kinet/crypto/metal_mlkem.h"
#include <cstdlib>
#include <cstring>

#ifdef __APPLE__
#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#endif

// External CPU implementations from crypto.cpp (mode-aware versions)
extern "C" {
    int mlkem_keygen(int mode, uint8_t* pk, uint8_t* sk, const uint8_t* seed);
    int mlkem_encaps(int mode, uint8_t* ct, uint8_t* ss, const uint8_t* pk, const uint8_t* randomness);
    int mlkem_decaps(int mode, uint8_t* ss, const uint8_t* ct, const uint8_t* sk);
    int mlkem_batch_encaps(int mode, uint8_t** cts, uint8_t* ss,
                           const uint8_t* const* pks, const uint8_t* randomness,
                           uint32_t count);
    int mlkem_batch_decaps(int mode, uint8_t* ss, const uint8_t* const* cts,
                           const uint8_t* sk, uint32_t count);
}

// =============================================================================
// Context Structure
// =============================================================================

struct MetalMLKEMContext {
#ifdef __APPLE__
    id<MTLDevice> device;
    id<MTLCommandQueue> queue;
    id<MTLLibrary> library;
    bool gpu_available;
#else
    bool gpu_available;
#endif
};

// =============================================================================
// Context Management
// =============================================================================

MetalMLKEMContext* metal_mlkem_init(void) {
    MetalMLKEMContext* ctx = new MetalMLKEMContext();
    ctx->gpu_available = false;

#ifdef __APPLE__
    @autoreleasepool {
        ctx->device = MTLCreateSystemDefaultDevice();
        if (ctx->device) {
            ctx->queue = [ctx->device newCommandQueue];
            ctx->gpu_available = (ctx->queue != nil);
            // TODO: Load NTT compute shaders when implemented
        }
    }
#endif

    return ctx;
}

void metal_mlkem_destroy(MetalMLKEMContext* ctx) {
    if (ctx) {
#ifdef __APPLE__
        @autoreleasepool {
            ctx->queue = nil;
            ctx->library = nil;
            ctx->device = nil;
        }
#endif
        delete ctx;
    }
}

bool metal_mlkem_available(void) {
#ifdef __APPLE__
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        return device != nil;
    }
#else
    return false;
#endif
}

// =============================================================================
// Key Generation
// =============================================================================

int metal_mlkem_keygen(
    MetalMLKEMContext* ctx,
    MLKEMMode mode,
    uint8_t* public_key,
    uint8_t* secret_key,
    const uint8_t* seed)
{
    if (!ctx || !public_key || !secret_key || !seed) {
        return METAL_MLKEM_ERROR_NULL_PTR;
    }

    // Use CPU implementation (GPU NTT acceleration TODO)
    return mlkem_keygen((int)mode, public_key, secret_key, seed);
}

// =============================================================================
// Encapsulation Operations
// =============================================================================

int metal_mlkem_encaps(
    MetalMLKEMContext* ctx,
    MLKEMMode mode,
    uint8_t* ciphertext,
    uint8_t* shared_secret,
    const uint8_t* public_key,
    const uint8_t* randomness)
{
    if (!ctx || !ciphertext || !shared_secret || !public_key || !randomness) {
        return METAL_MLKEM_ERROR_NULL_PTR;
    }

    return mlkem_encaps((int)mode, ciphertext, shared_secret, public_key, randomness);
}

int metal_mlkem_batch_encaps(
    MetalMLKEMContext* ctx,
    MLKEMMode mode,
    uint8_t** ciphertexts,
    uint8_t* shared_secrets,
    const uint8_t* const* public_keys,
    const uint8_t* randomness,
    uint32_t count)
{
    if (!ctx || !ciphertexts || !shared_secrets || !public_keys || !randomness) {
        return METAL_MLKEM_ERROR_NULL_PTR;
    }

    if (count == 0) {
        return METAL_MLKEM_SUCCESS;
    }

    return mlkem_batch_encaps((int)mode, ciphertexts, shared_secrets,
                              public_keys, randomness, count);
}

// =============================================================================
// Decapsulation Operations
// =============================================================================

int metal_mlkem_decaps(
    MetalMLKEMContext* ctx,
    MLKEMMode mode,
    uint8_t* shared_secret,
    const uint8_t* ciphertext,
    const uint8_t* secret_key)
{
    if (!ctx || !shared_secret || !ciphertext || !secret_key) {
        return METAL_MLKEM_ERROR_NULL_PTR;
    }

    return mlkem_decaps((int)mode, shared_secret, ciphertext, secret_key);
}

int metal_mlkem_batch_decaps(
    MetalMLKEMContext* ctx,
    MLKEMMode mode,
    uint8_t* shared_secrets,
    const uint8_t* const* ciphertexts,
    const uint8_t* secret_key,
    uint32_t count)
{
    if (!ctx || !shared_secrets || !ciphertexts || !secret_key) {
        return METAL_MLKEM_ERROR_NULL_PTR;
    }

    if (count == 0) {
        return METAL_MLKEM_SUCCESS;
    }

    return mlkem_batch_decaps((int)mode, shared_secrets, ciphertexts,
                              secret_key, count);
}

// =============================================================================
// NTT Operations (Placeholder for GPU implementation)
// =============================================================================

int metal_mlkem_batch_ntt(
    MetalMLKEMContext* ctx,
    MLKEMPoly* out,
    const MLKEMPoly* in,
    uint32_t count)
{
    // TODO: Implement GPU-accelerated NTT
    (void)ctx;
    (void)out;
    (void)in;
    (void)count;
    return METAL_MLKEM_ERROR_INVALID;
}

int metal_mlkem_batch_intt(
    MetalMLKEMContext* ctx,
    MLKEMPoly* out,
    const MLKEMPoly* in,
    uint32_t count)
{
    // TODO: Implement GPU-accelerated INTT
    (void)ctx;
    (void)out;
    (void)in;
    (void)count;
    return METAL_MLKEM_ERROR_INVALID;
}

int metal_mlkem_batch_poly_mul(
    MetalMLKEMContext* ctx,
    MLKEMPoly* out,
    const MLKEMPoly* a,
    const MLKEMPoly* b,
    uint32_t count)
{
    // TODO: Implement GPU-accelerated polynomial multiplication
    (void)ctx;
    (void)out;
    (void)a;
    (void)b;
    (void)count;
    return METAL_MLKEM_ERROR_INVALID;
}

int metal_mlkem_matvec_mul(
    MetalMLKEMContext* ctx,
    MLKEMMode mode,
    MLKEMPoly* out,
    const MLKEMPoly* matrix,
    const MLKEMPoly* vector)
{
    // TODO: Implement GPU-accelerated matrix-vector multiplication
    (void)ctx;
    (void)mode;
    (void)out;
    (void)matrix;
    (void)vector;
    return METAL_MLKEM_ERROR_INVALID;
}

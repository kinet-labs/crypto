// =============================================================================
// Metal SLH-DSA - GPU Acceleration for Hash-Based Signatures
// =============================================================================
//
// Implementation of SLH-DSA (FIPS 205) with Metal GPU acceleration.
// Falls back to CPU implementation when GPU is not available.
//

#include "kinet/crypto/metal_slhdsa.h"
#include <cstdlib>
#include <cstring>

#ifdef __APPLE__
#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#endif

// External CPU implementations from crypto.cpp (mode-aware versions)
extern "C" {
    int slhdsa_keygen(int mode, uint8_t* pk, uint8_t* sk, const uint8_t* seed);
    int slhdsa_sign(int mode, uint8_t* sig, const uint8_t* sk,
                    const uint8_t* msg, size_t msg_len);
    int slhdsa_verify(int mode, const uint8_t* pk, const uint8_t* sig,
                      const uint8_t* msg, size_t msg_len);
    int slhdsa_batch_sign(int mode, uint8_t** sigs, const uint8_t* sk,
                          const uint8_t* const* msgs, const size_t* msg_lens,
                          uint32_t count);
    int slhdsa_batch_verify(int mode, const uint8_t* const* pks,
                            const uint8_t* const* sigs,
                            const uint8_t* const* msgs,
                            const size_t* msg_lens,
                            uint32_t count, int* results);
}

// =============================================================================
// Context Structure
// =============================================================================

struct MetalSLHDSAContext {
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

MetalSLHDSAContext* metal_slhdsa_init(void) {
    MetalSLHDSAContext* ctx = new MetalSLHDSAContext();
    ctx->gpu_available = false;

#ifdef __APPLE__
    @autoreleasepool {
        ctx->device = MTLCreateSystemDefaultDevice();
        if (ctx->device) {
            ctx->queue = [ctx->device newCommandQueue];
            ctx->gpu_available = (ctx->queue != nil);
            // TODO: Load hash compute shaders when implemented
        }
    }
#endif

    return ctx;
}

void metal_slhdsa_destroy(MetalSLHDSAContext* ctx) {
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

bool metal_slhdsa_available(void) {
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

int metal_slhdsa_keygen(
    MetalSLHDSAContext* ctx,
    SLHDSAMode mode,
    uint8_t* public_key,
    uint8_t* secret_key,
    const uint8_t* seed)
{
    if (!ctx || !public_key || !secret_key || !seed) {
        return METAL_SLHDSA_ERROR_NULL_PTR;
    }

    // Use CPU implementation (GPU hash tree acceleration TODO)
    return slhdsa_keygen((int)mode, public_key, secret_key, seed);
}

// =============================================================================
// Signing Operations
// =============================================================================

int metal_slhdsa_sign(
    MetalSLHDSAContext* ctx,
    SLHDSAMode mode,
    uint8_t* signature,
    const uint8_t* secret_key,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* context,
    size_t context_len)
{
    if (!ctx || !signature || !secret_key || !message) {
        return METAL_SLHDSA_ERROR_NULL_PTR;
    }

    // TODO: Add context support
    (void)context;
    (void)context_len;

    return slhdsa_sign((int)mode, signature, secret_key, message, message_len);
}

int metal_slhdsa_batch_sign(
    MetalSLHDSAContext* ctx,
    SLHDSAMode mode,
    uint8_t** signatures,
    const uint8_t* secret_key,
    const uint8_t* const* messages,
    const size_t* message_lens,
    uint32_t count)
{
    if (!ctx || !signatures || !secret_key || !messages || !message_lens) {
        return METAL_SLHDSA_ERROR_NULL_PTR;
    }

    if (count == 0) {
        return METAL_SLHDSA_SUCCESS;
    }

    return slhdsa_batch_sign((int)mode, signatures, secret_key,
                             messages, message_lens, count);
}

// =============================================================================
// Verification Operations
// =============================================================================

int metal_slhdsa_verify(
    MetalSLHDSAContext* ctx,
    SLHDSAMode mode,
    const uint8_t* public_key,
    const uint8_t* signature,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* context,
    size_t context_len)
{
    if (!ctx || !public_key || !signature || !message) {
        return METAL_SLHDSA_ERROR_NULL_PTR;
    }

    // TODO: Add context support
    (void)context;
    (void)context_len;

    return slhdsa_verify((int)mode, public_key, signature, message, message_len);
}

int metal_slhdsa_batch_verify(
    MetalSLHDSAContext* ctx,
    SLHDSAMode mode,
    const uint8_t* const* public_keys,
    const uint8_t* const* signatures,
    const uint8_t* const* messages,
    const size_t* message_lens,
    uint32_t count,
    int* results)
{
    if (!ctx || !public_keys || !signatures || !messages || !message_lens || !results) {
        return METAL_SLHDSA_ERROR_NULL_PTR;
    }

    return slhdsa_batch_verify((int)mode, public_keys, signatures, messages,
                               message_lens, count, results);
}

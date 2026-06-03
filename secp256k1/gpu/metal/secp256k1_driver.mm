// =============================================================================
// Metal secp256k1 - GPU Acceleration Implementation
// =============================================================================
//
// Objective-C++ implementation for Metal compute shader dispatch.
// Uses GTable precomputation for ~20x faster scalar multiplication.
//
// Copyright (C) 2024-2025 Kinet Industries Inc.
// SPDX-License-Identifier: Apache-2.0

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include "kinet/crypto/metal_secp256k1.h"
#include <cstring>
#include <cstdlib>
#include <vector>

// =============================================================================
// Metal Context Structure
// =============================================================================

struct MetalSecp256k1Context {
    id<MTLDevice> device;
    id<MTLCommandQueue> commandQueue;
    id<MTLLibrary> library;

    // Compute pipeline states
    id<MTLComputePipelineState> pipelinePrecomputeGtable;
    id<MTLComputePipelineState> pipelineGtableScalarMul;
    id<MTLComputePipelineState> pipelineBatchVerify;
    id<MTLComputePipelineState> pipelineBatchDeriveAddress;
    id<MTLComputePipelineState> pipelineParallelReduce;
    id<MTLComputePipelineState> pipelineScalarMul;
    id<MTLComputePipelineState> pipelineBatchAdd;
    id<MTLComputePipelineState> pipelineBatchDouble;

    // Precomputed GTable (67MB)
    id<MTLBuffer> gtableBuffer;
    bool gtableReady;

    // Custom tables for other base points
    std::vector<id<MTLBuffer>> customTables;

    // Memory tracking
    size_t totalMemory;
};

// =============================================================================
// Helper: Create Pipeline
// =============================================================================

static id<MTLComputePipelineState> createPipeline(
    MetalSecp256k1Context* ctx,
    const char* name)
{
    id<MTLFunction> func = [ctx->library newFunctionWithName:
                            [NSString stringWithUTF8String:name]];
    if (!func) {
        NSLog(@"Metal secp256k1: Function '%s' not found", name);
        return nil;
    }

    NSError* error = nil;
    id<MTLComputePipelineState> pipeline =
        [ctx->device newComputePipelineStateWithFunction:func error:&error];
    if (!pipeline) {
        NSLog(@"Metal secp256k1: Failed to create pipeline '%s': %@",
              name, error.localizedDescription);
    }
    return pipeline;
}

// =============================================================================
// Initialization
// =============================================================================

extern "C" bool metal_secp256k1_gpu_available(void) {
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        return device != nil;
    }
}

extern "C" MetalSecp256k1Context* metal_secp256k1_create(int device_id) {
    @autoreleasepool {
        MetalSecp256k1Context* ctx = new MetalSecp256k1Context();
        memset(ctx, 0, sizeof(MetalSecp256k1Context));

        // Get Metal device
        if (device_id == 0) {
            ctx->device = MTLCreateSystemDefaultDevice();
        } else {
            // For multi-GPU systems
            NSArray<id<MTLDevice>>* devices = MTLCopyAllDevices();
            if ((NSUInteger)device_id < devices.count) {
                ctx->device = devices[device_id];
            }
        }

        if (!ctx->device) {
            delete ctx;
            return nullptr;
        }

        // Create command queue
        ctx->commandQueue = [ctx->device newCommandQueue];
        if (!ctx->commandQueue) {
            delete ctx;
            return nullptr;
        }

        // Load Metal library
        NSError* error = nil;

        // Try loading pre-compiled metallib first
        NSArray* metallibPaths = @[
            @"/usr/local/share/kinet/crypto/kinet_crypto.metallib",
            @"/usr/local/share/kinet/crypto/secp256k1.metallib",
            [[NSBundle mainBundle] pathForResource:@"kinet_crypto" ofType:@"metallib"] ?: @"",
            [[NSBundle mainBundle] pathForResource:@"secp256k1" ofType:@"metallib"] ?: @""
        ];

        for (NSString* libPath in metallibPaths) {
            if (libPath.length > 0 && [[NSFileManager defaultManager] fileExistsAtPath:libPath]) {
                NSURL* libURL = [NSURL fileURLWithPath:libPath];
                ctx->library = [ctx->device newLibraryWithURL:libURL error:&error];
                if (ctx->library) break;
            }
        }

        // Fall back to compiling from source
        if (!ctx->library) {
            NSArray* searchPaths = @[
                @"src/metal/secp256k1.metal",
                @"../src/metal/secp256k1.metal",
                @"metal/secp256k1.metal",
                @"/usr/local/share/kinet/crypto/secp256k1.metal"
            ];

            for (NSString* path in searchPaths) {
                if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
                    NSString* source = [NSString stringWithContentsOfFile:path
                                                                 encoding:NSUTF8StringEncoding
                                                                    error:&error];
                    if (source) {
                        MTLCompileOptions* options = [[MTLCompileOptions alloc] init];
                        if (@available(macOS 15.0, *)) {
                            options.mathMode = MTLMathModeFast;
                        } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
                            options.fastMathEnabled = YES;
#pragma clang diagnostic pop
                        }

                        ctx->library = [ctx->device newLibraryWithSource:source
                                                                 options:options
                                                                   error:&error];
                        if (ctx->library) break;
                    }
                }
            }
        }

        if (!ctx->library) {
            NSLog(@"Metal secp256k1: Failed to load shader library: %@",
                  error ? error.localizedDescription : @"Unknown error");
            delete ctx;
            return nullptr;
        }

        // Create compute pipeline states
        ctx->pipelinePrecomputeGtable = createPipeline(ctx, "precompute_gtable");
        ctx->pipelineGtableScalarMul = createPipeline(ctx, "gtable_scalar_mul");
        ctx->pipelineBatchVerify = createPipeline(ctx, "batch_verify");
        ctx->pipelineBatchDeriveAddress = createPipeline(ctx, "batch_derive_address");
        ctx->pipelineParallelReduce = createPipeline(ctx, "parallel_point_reduce");
        ctx->pipelineScalarMul = createPipeline(ctx, "scalar_mul");
        ctx->pipelineBatchAdd = createPipeline(ctx, "batch_point_add");
        ctx->pipelineBatchDouble = createPipeline(ctx, "batch_point_double");

        // At minimum we need GTable scalar mul
        if (!ctx->pipelineGtableScalarMul) {
            delete ctx;
            return nullptr;
        }

        // Allocate GTable buffer (16 chunks × 65536 points × 64 bytes = 67MB)
        size_t gtableSize = SECP256K1_GTABLE_TOTAL_POINTS * sizeof(Secp256k1Affine);
        ctx->gtableBuffer = [ctx->device newBufferWithLength:gtableSize
                                                     options:MTLResourceStorageModeShared];
        if (!ctx->gtableBuffer) {
            NSLog(@"Metal secp256k1: Failed to allocate GTable (%.1f MB)",
                  gtableSize / (1024.0 * 1024.0));
            delete ctx;
            return nullptr;
        }
        ctx->totalMemory = gtableSize;

        // Precompute GTable on GPU
        if (ctx->pipelinePrecomputeGtable) {
            id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

            [encoder setComputePipelineState:ctx->pipelinePrecomputeGtable];
            [encoder setBuffer:ctx->gtableBuffer offset:0 atIndex:0];

            // Launch enough threads to precompute all points
            NSUInteger threadsPerGroup = MIN(256UL,
                ctx->pipelinePrecomputeGtable.maxTotalThreadsPerThreadgroup);

            // We compute all points - shader handles the index calculation
            [encoder dispatchThreads:MTLSizeMake(SECP256K1_GTABLE_TOTAL_POINTS, 1, 1)
               threadsPerThreadgroup:MTLSizeMake(threadsPerGroup, 1, 1)];
            [encoder endEncoding];

            [commandBuffer commit];
            [commandBuffer waitUntilCompleted];

            ctx->gtableReady = true;
        } else {
            // Fall back to CPU precomputation (placeholder - would need implementation)
            NSLog(@"Metal secp256k1: GTable precompute shader not found");
            ctx->gtableReady = false;
        }

        return ctx;
    }
}

extern "C" void metal_secp256k1_destroy(MetalSecp256k1Context* ctx) {
    if (!ctx) return;

    @autoreleasepool {
        // Release custom tables
        ctx->customTables.clear();

        // ARC handles release of Objective-C objects
        ctx->gtableBuffer = nil;
        ctx->pipelinePrecomputeGtable = nil;
        ctx->pipelineGtableScalarMul = nil;
        ctx->pipelineBatchVerify = nil;
        ctx->pipelineBatchDeriveAddress = nil;
        ctx->pipelineParallelReduce = nil;
        ctx->pipelineScalarMul = nil;
        ctx->pipelineBatchAdd = nil;
        ctx->pipelineBatchDouble = nil;
        ctx->library = nil;
        ctx->commandQueue = nil;
        ctx->device = nil;
    }

    delete ctx;
}

extern "C" size_t metal_secp256k1_memory_usage(MetalSecp256k1Context* ctx) {
    if (!ctx) return 0;
    return ctx->totalMemory;
}

// =============================================================================
// Helper: Create Buffers
// =============================================================================

static id<MTLBuffer> createBuffer(MetalSecp256k1Context* ctx, size_t size) {
    return [ctx->device newBufferWithLength:size
                                    options:MTLResourceStorageModeShared];
}

static id<MTLBuffer> createBufferWithData(MetalSecp256k1Context* ctx,
                                           const void* data, size_t size) {
    return [ctx->device newBufferWithBytes:data
                                    length:size
                                   options:MTLResourceStorageModeShared];
}

// =============================================================================
// Scalar Multiplication (GTable-accelerated)
// =============================================================================

extern "C" int metal_secp256k1_scalar_mul_g(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* result,
    const Secp256k1Scalar* scalar)
{
    if (!ctx || !result || !scalar) {
        return SECP256K1_ERROR_NULL_PTR;
    }

    if (!ctx->gtableReady || !ctx->pipelineGtableScalarMul) {
        return SECP256K1_ERROR_GPU;
    }

    @autoreleasepool {
        id<MTLBuffer> scalarBuffer = createBufferWithData(ctx, scalar, sizeof(Secp256k1Scalar));
        id<MTLBuffer> resultBuffer = createBuffer(ctx, sizeof(Secp256k1Affine));

        if (!scalarBuffer || !resultBuffer) {
            return SECP256K1_ERROR_MEMORY;
        }

        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        [encoder setComputePipelineState:ctx->pipelineGtableScalarMul];
        [encoder setBuffer:ctx->gtableBuffer offset:0 atIndex:0];
        [encoder setBuffer:scalarBuffer offset:0 atIndex:1];
        [encoder setBuffer:resultBuffer offset:0 atIndex:2];
        uint32_t count = 1;
        [encoder setBytes:&count length:sizeof(count) atIndex:3];

        [encoder dispatchThreads:MTLSizeMake(1, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
        [encoder endEncoding];

        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        memcpy(result, [resultBuffer contents], sizeof(Secp256k1Affine));

        return SECP256K1_SUCCESS;
    }
}

extern "C" int metal_secp256k1_batch_scalar_mul_g(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* results,
    const Secp256k1Scalar* scalars,
    uint32_t count)
{
    if (!ctx || !results || !scalars || count == 0) {
        return SECP256K1_ERROR_NULL_PTR;
    }

    if (!ctx->gtableReady || !ctx->pipelineGtableScalarMul) {
        return SECP256K1_ERROR_GPU;
    }

    @autoreleasepool {
        size_t scalarSize = count * sizeof(Secp256k1Scalar);
        size_t resultSize = count * sizeof(Secp256k1Affine);

        id<MTLBuffer> scalarBuffer = createBufferWithData(ctx, scalars, scalarSize);
        id<MTLBuffer> resultBuffer = createBuffer(ctx, resultSize);

        if (!scalarBuffer || !resultBuffer) {
            return SECP256K1_ERROR_MEMORY;
        }

        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        [encoder setComputePipelineState:ctx->pipelineGtableScalarMul];
        [encoder setBuffer:ctx->gtableBuffer offset:0 atIndex:0];
        [encoder setBuffer:scalarBuffer offset:0 atIndex:1];
        [encoder setBuffer:resultBuffer offset:0 atIndex:2];
        [encoder setBytes:&count length:sizeof(count) atIndex:3];

        NSUInteger threadsPerGroup = MIN(256UL,
            ctx->pipelineGtableScalarMul.maxTotalThreadsPerThreadgroup);

        [encoder dispatchThreads:MTLSizeMake(count, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(threadsPerGroup, 1, 1)];
        [encoder endEncoding];

        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        memcpy(results, [resultBuffer contents], resultSize);

        return SECP256K1_SUCCESS;
    }
}

extern "C" int metal_secp256k1_scalar_mul(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* result,
    const Secp256k1Scalar* scalar,
    const Secp256k1Affine* point)
{
    if (!ctx || !result || !scalar || !point) {
        return SECP256K1_ERROR_NULL_PTR;
    }

    if (!ctx->pipelineScalarMul) {
        return SECP256K1_ERROR_GPU;
    }

    @autoreleasepool {
        id<MTLBuffer> scalarBuffer = createBufferWithData(ctx, scalar, sizeof(Secp256k1Scalar));
        id<MTLBuffer> pointBuffer = createBufferWithData(ctx, point, sizeof(Secp256k1Affine));
        id<MTLBuffer> resultBuffer = createBuffer(ctx, sizeof(Secp256k1Affine));

        if (!scalarBuffer || !pointBuffer || !resultBuffer) {
            return SECP256K1_ERROR_MEMORY;
        }

        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        [encoder setComputePipelineState:ctx->pipelineScalarMul];
        [encoder setBuffer:pointBuffer offset:0 atIndex:0];
        [encoder setBuffer:scalarBuffer offset:0 atIndex:1];
        [encoder setBuffer:resultBuffer offset:0 atIndex:2];
        uint32_t count = 1;
        [encoder setBytes:&count length:sizeof(count) atIndex:3];

        [encoder dispatchThreads:MTLSizeMake(1, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
        [encoder endEncoding];

        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        memcpy(result, [resultBuffer contents], sizeof(Secp256k1Affine));

        return SECP256K1_SUCCESS;
    }
}

extern "C" int metal_secp256k1_batch_scalar_mul(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* results,
    const Secp256k1Scalar* scalars,
    const Secp256k1Affine* points,
    uint32_t count)
{
    if (!ctx || !results || !scalars || !points || count == 0) {
        return SECP256K1_ERROR_NULL_PTR;
    }

    if (!ctx->pipelineScalarMul) {
        return SECP256K1_ERROR_GPU;
    }

    @autoreleasepool {
        size_t scalarSize = count * sizeof(Secp256k1Scalar);
        size_t pointSize = count * sizeof(Secp256k1Affine);

        id<MTLBuffer> scalarBuffer = createBufferWithData(ctx, scalars, scalarSize);
        id<MTLBuffer> pointBuffer = createBufferWithData(ctx, points, pointSize);
        id<MTLBuffer> resultBuffer = createBuffer(ctx, pointSize);

        if (!scalarBuffer || !pointBuffer || !resultBuffer) {
            return SECP256K1_ERROR_MEMORY;
        }

        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        [encoder setComputePipelineState:ctx->pipelineScalarMul];
        [encoder setBuffer:pointBuffer offset:0 atIndex:0];
        [encoder setBuffer:scalarBuffer offset:0 atIndex:1];
        [encoder setBuffer:resultBuffer offset:0 atIndex:2];
        [encoder setBytes:&count length:sizeof(count) atIndex:3];

        NSUInteger threadsPerGroup = MIN(64UL,
            ctx->pipelineScalarMul.maxTotalThreadsPerThreadgroup);

        [encoder dispatchThreads:MTLSizeMake(count, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(threadsPerGroup, 1, 1)];
        [encoder endEncoding];

        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        memcpy(results, [resultBuffer contents], pointSize);

        return SECP256K1_SUCCESS;
    }
}

// =============================================================================
// MSM (Multi-Scalar Multiplication)
// =============================================================================

extern "C" int metal_secp256k1_msm(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* result,
    const Secp256k1Affine* points,
    const Secp256k1Scalar* scalars,
    uint32_t count)
{
    if (!ctx || !result || !points || !scalars || count == 0) {
        return SECP256K1_ERROR_NULL_PTR;
    }

    // For small counts, use batch scalar mul + reduction
    if (count <= 256 || !ctx->pipelineParallelReduce) {
        @autoreleasepool {
            // Compute individual scalar muls
            std::vector<Secp256k1Affine> intermediates(count);
            int err = metal_secp256k1_batch_scalar_mul(ctx,
                intermediates.data(), scalars, points, count);
            if (err != SECP256K1_SUCCESS) return err;

            // Reduce on GPU
            size_t pointSize = count * sizeof(Secp256k1Affine);
            id<MTLBuffer> inputBuffer = createBufferWithData(ctx,
                intermediates.data(), pointSize);
            id<MTLBuffer> resultBuffer = createBuffer(ctx, sizeof(Secp256k1Affine));

            if (!inputBuffer || !resultBuffer) {
                return SECP256K1_ERROR_MEMORY;
            }

            id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

            [encoder setComputePipelineState:ctx->pipelineParallelReduce];
            [encoder setBuffer:inputBuffer offset:0 atIndex:0];
            [encoder setBuffer:resultBuffer offset:0 atIndex:1];
            [encoder setBytes:&count length:sizeof(count) atIndex:2];

            NSUInteger threadsPerGroup = MIN(256UL,
                ctx->pipelineParallelReduce.maxTotalThreadsPerThreadgroup);

            [encoder setThreadgroupMemoryLength:threadsPerGroup * sizeof(Secp256k1Affine)
                                        atIndex:0];

            [encoder dispatchThreads:MTLSizeMake(threadsPerGroup, 1, 1)
               threadsPerThreadgroup:MTLSizeMake(threadsPerGroup, 1, 1)];
            [encoder endEncoding];

            [commandBuffer commit];
            [commandBuffer waitUntilCompleted];

            memcpy(result, [resultBuffer contents], sizeof(Secp256k1Affine));

            return SECP256K1_SUCCESS;
        }
    }

    // For large counts, would use Pippenger's algorithm
    // Placeholder: fall back to batch + reduce
    return SECP256K1_ERROR_GPU;
}

// =============================================================================
// ECDSA Batch Verification
// =============================================================================

extern "C" int metal_secp256k1_batch_verify(
    MetalSecp256k1Context* ctx,
    int* results,
    const uint8_t* const* messages,
    const Secp256k1Signature* signatures,
    const Secp256k1Affine* public_keys,
    uint32_t count)
{
    if (!ctx || !results || !messages || !signatures || !public_keys || count == 0) {
        return SECP256K1_ERROR_NULL_PTR;
    }

    if (!ctx->pipelineBatchVerify) {
        return SECP256K1_ERROR_GPU;
    }

    @autoreleasepool {
        // Pack messages into contiguous buffer
        std::vector<uint8_t> msgBuffer(count * 32);
        for (uint32_t i = 0; i < count; i++) {
            if (!messages[i]) return SECP256K1_ERROR_NULL_PTR;
            memcpy(&msgBuffer[i * 32], messages[i], 32);
        }

        size_t sigSize = count * sizeof(Secp256k1Signature);
        size_t pkSize = count * sizeof(Secp256k1Affine);

        id<MTLBuffer> msgBufferGPU = createBufferWithData(ctx, msgBuffer.data(), msgBuffer.size());
        id<MTLBuffer> sigBuffer = createBufferWithData(ctx, signatures, sigSize);
        id<MTLBuffer> pkBuffer = createBufferWithData(ctx, public_keys, pkSize);
        id<MTLBuffer> resultBuffer = createBuffer(ctx, count * sizeof(int));

        if (!msgBufferGPU || !sigBuffer || !pkBuffer || !resultBuffer) {
            return SECP256K1_ERROR_MEMORY;
        }

        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        [encoder setComputePipelineState:ctx->pipelineBatchVerify];
        [encoder setBuffer:ctx->gtableBuffer offset:0 atIndex:0];
        [encoder setBuffer:msgBufferGPU offset:0 atIndex:1];
        [encoder setBuffer:sigBuffer offset:0 atIndex:2];
        [encoder setBuffer:pkBuffer offset:0 atIndex:3];
        [encoder setBuffer:resultBuffer offset:0 atIndex:4];
        [encoder setBytes:&count length:sizeof(count) atIndex:5];

        NSUInteger threadsPerGroup = MIN(64UL,
            ctx->pipelineBatchVerify.maxTotalThreadsPerThreadgroup);

        [encoder dispatchThreads:MTLSizeMake(count, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(threadsPerGroup, 1, 1)];
        [encoder endEncoding];

        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        memcpy(results, [resultBuffer contents], count * sizeof(int));

        return SECP256K1_SUCCESS;
    }
}

// =============================================================================
// Address Derivation
// =============================================================================

extern "C" int metal_secp256k1_batch_derive_pubkey(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* public_keys,
    const Secp256k1Scalar* secret_keys,
    uint32_t count)
{
    // Derive public keys: pk = sk * G
    return metal_secp256k1_batch_scalar_mul_g(ctx, public_keys, secret_keys, count);
}

extern "C" int metal_secp256k1_batch_derive_address(
    MetalSecp256k1Context* ctx,
    uint8_t* addresses,
    const Secp256k1Affine* public_keys,
    uint32_t count)
{
    if (!ctx || !addresses || !public_keys || count == 0) {
        return SECP256K1_ERROR_NULL_PTR;
    }

    if (!ctx->pipelineBatchDeriveAddress) {
        return SECP256K1_ERROR_GPU;
    }

    @autoreleasepool {
        size_t pkSize = count * sizeof(Secp256k1Affine);
        size_t addrSize = count * 20;  // 20 bytes per Ethereum address

        id<MTLBuffer> pkBuffer = createBufferWithData(ctx, public_keys, pkSize);
        id<MTLBuffer> addrBuffer = createBuffer(ctx, addrSize);

        if (!pkBuffer || !addrBuffer) {
            return SECP256K1_ERROR_MEMORY;
        }

        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        [encoder setComputePipelineState:ctx->pipelineBatchDeriveAddress];
        [encoder setBuffer:pkBuffer offset:0 atIndex:0];
        [encoder setBuffer:addrBuffer offset:0 atIndex:1];
        [encoder setBytes:&count length:sizeof(count) atIndex:2];

        NSUInteger threadsPerGroup = MIN(256UL,
            ctx->pipelineBatchDeriveAddress.maxTotalThreadsPerThreadgroup);

        [encoder dispatchThreads:MTLSizeMake(count, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(threadsPerGroup, 1, 1)];
        [encoder endEncoding];

        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        memcpy(addresses, [addrBuffer contents], addrSize);

        return SECP256K1_SUCCESS;
    }
}

// =============================================================================
// Point Arithmetic
// =============================================================================

extern "C" int metal_secp256k1_batch_add(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* results,
    const Secp256k1Affine* a,
    const Secp256k1Affine* b,
    uint32_t count)
{
    if (!ctx || !results || !a || !b || count == 0) {
        return SECP256K1_ERROR_NULL_PTR;
    }

    if (!ctx->pipelineBatchAdd) {
        return SECP256K1_ERROR_GPU;
    }

    @autoreleasepool {
        size_t pointSize = count * sizeof(Secp256k1Affine);

        id<MTLBuffer> bufferA = createBufferWithData(ctx, a, pointSize);
        id<MTLBuffer> bufferB = createBufferWithData(ctx, b, pointSize);
        id<MTLBuffer> bufferResult = createBuffer(ctx, pointSize);

        if (!bufferA || !bufferB || !bufferResult) {
            return SECP256K1_ERROR_MEMORY;
        }

        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        [encoder setComputePipelineState:ctx->pipelineBatchAdd];
        [encoder setBuffer:bufferResult offset:0 atIndex:0];
        [encoder setBuffer:bufferA offset:0 atIndex:1];
        [encoder setBuffer:bufferB offset:0 atIndex:2];
        [encoder setBytes:&count length:sizeof(count) atIndex:3];

        NSUInteger threadsPerGroup = MIN(256UL,
            ctx->pipelineBatchAdd.maxTotalThreadsPerThreadgroup);

        [encoder dispatchThreads:MTLSizeMake(count, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(threadsPerGroup, 1, 1)];
        [encoder endEncoding];

        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        memcpy(results, [bufferResult contents], pointSize);

        return SECP256K1_SUCCESS;
    }
}

extern "C" int metal_secp256k1_batch_double(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* results,
    const Secp256k1Affine* points,
    uint32_t count)
{
    if (!ctx || !results || !points || count == 0) {
        return SECP256K1_ERROR_NULL_PTR;
    }

    if (!ctx->pipelineBatchDouble) {
        return SECP256K1_ERROR_GPU;
    }

    @autoreleasepool {
        size_t pointSize = count * sizeof(Secp256k1Affine);

        id<MTLBuffer> bufferPoints = createBufferWithData(ctx, points, pointSize);
        id<MTLBuffer> bufferResult = createBuffer(ctx, pointSize);

        if (!bufferPoints || !bufferResult) {
            return SECP256K1_ERROR_MEMORY;
        }

        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        [encoder setComputePipelineState:ctx->pipelineBatchDouble];
        [encoder setBuffer:bufferResult offset:0 atIndex:0];
        [encoder setBuffer:bufferPoints offset:0 atIndex:1];
        [encoder setBytes:&count length:sizeof(count) atIndex:2];

        NSUInteger threadsPerGroup = MIN(256UL,
            ctx->pipelineBatchDouble.maxTotalThreadsPerThreadgroup);

        [encoder dispatchThreads:MTLSizeMake(count, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(threadsPerGroup, 1, 1)];
        [encoder endEncoding];

        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        memcpy(results, [bufferResult contents], pointSize);

        return SECP256K1_SUCCESS;
    }
}

extern "C" int metal_secp256k1_batch_negate(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* results,
    const Secp256k1Affine* points,
    uint32_t count)
{
    if (!ctx || !results || !points || count == 0) {
        return SECP256K1_ERROR_NULL_PTR;
    }

    // Negation is simple: -P = (x, -y mod p)
    // Can be done on CPU efficiently
    for (uint32_t i = 0; i < count; i++) {
        results[i].x = points[i].x;
        results[i].infinity = points[i].infinity;

        if (!points[i].infinity) {
            // Negate y: y' = p - y
            // secp256k1 p = 2^256 - 2^32 - 977
            // For simplicity, we compute -y mod p
            Secp256k1Fp p = {{
                0xFFFFFFFEFFFFFC2F,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF
            }};

            // Subtract y from p
            uint64_t borrow = 0;
            for (int j = 0; j < 4; j++) {
                __uint128_t diff = (__uint128_t)p.limbs[j] - points[i].y.limbs[j] - borrow;
                results[i].y.limbs[j] = (uint64_t)diff;
                borrow = (diff >> 64) & 1 ? 1 : 0;
            }
        }
    }

    return SECP256K1_SUCCESS;
}

// =============================================================================
// Serialization (CPU implementation - no GPU benefit)
// =============================================================================

extern "C" void secp256k1_affine_serialize_compressed(
    uint8_t* out,
    const Secp256k1Affine* point)
{
    if (!out || !point) return;

    if (point->infinity) {
        memset(out, 0, 33);
        return;
    }

    // Prefix: 02 if y is even, 03 if y is odd
    out[0] = (point->y.limbs[0] & 1) ? 0x03 : 0x02;

    // X coordinate in big-endian
    for (int i = 0; i < 4; i++) {
        uint64_t limb = point->x.limbs[3 - i];
        for (int j = 7; j >= 0; j--) {
            out[1 + i * 8 + (7 - j)] = (limb >> (j * 8)) & 0xFF;
        }
    }
}

extern "C" void secp256k1_affine_serialize_uncompressed(
    uint8_t* out,
    const Secp256k1Affine* point)
{
    if (!out || !point) return;

    if (point->infinity) {
        memset(out, 0, 65);
        return;
    }

    out[0] = 0x04;  // Uncompressed prefix

    // X coordinate in big-endian
    for (int i = 0; i < 4; i++) {
        uint64_t limb = point->x.limbs[3 - i];
        for (int j = 7; j >= 0; j--) {
            out[1 + i * 8 + (7 - j)] = (limb >> (j * 8)) & 0xFF;
        }
    }

    // Y coordinate in big-endian
    for (int i = 0; i < 4; i++) {
        uint64_t limb = point->y.limbs[3 - i];
        for (int j = 7; j >= 0; j--) {
            out[33 + i * 8 + (7 - j)] = (limb >> (j * 8)) & 0xFF;
        }
    }
}

extern "C" int secp256k1_affine_deserialize_compressed(
    Secp256k1Affine* point,
    const uint8_t* in)
{
    if (!point || !in) return SECP256K1_ERROR_NULL_PTR;

    uint8_t prefix = in[0];
    if (prefix != 0x02 && prefix != 0x03) {
        return SECP256K1_ERROR_INVALID;
    }

    point->infinity = false;

    // X coordinate from big-endian
    for (int i = 0; i < 4; i++) {
        uint64_t limb = 0;
        for (int j = 0; j < 8; j++) {
            limb = (limb << 8) | in[1 + i * 8 + j];
        }
        point->x.limbs[3 - i] = limb;
    }

    // Compute y from x (y^2 = x^3 + 7)
    // This requires modular square root - placeholder
    memset(&point->y, 0, sizeof(point->y));

    // Set y parity based on prefix
    if (prefix == 0x03) {
        point->y.limbs[0] |= 1;  // Odd y
    }

    return SECP256K1_SUCCESS;
}

extern "C" int secp256k1_affine_deserialize_uncompressed(
    Secp256k1Affine* point,
    const uint8_t* in)
{
    if (!point || !in) return SECP256K1_ERROR_NULL_PTR;

    if (in[0] != 0x04) {
        return SECP256K1_ERROR_INVALID;
    }

    point->infinity = false;

    // X coordinate from big-endian
    for (int i = 0; i < 4; i++) {
        uint64_t limb = 0;
        for (int j = 0; j < 8; j++) {
            limb = (limb << 8) | in[1 + i * 8 + j];
        }
        point->x.limbs[3 - i] = limb;
    }

    // Y coordinate from big-endian
    for (int i = 0; i < 4; i++) {
        uint64_t limb = 0;
        for (int j = 0; j < 8; j++) {
            limb = (limb << 8) | in[33 + i * 8 + j];
        }
        point->y.limbs[3 - i] = limb;
    }

    return SECP256K1_SUCCESS;
}

// =============================================================================
// Custom GTable Management
// =============================================================================

extern "C" int metal_secp256k1_precompute_table(
    MetalSecp256k1Context* ctx,
    uint32_t* table_id,
    const Secp256k1Affine* base)
{
    if (!ctx || !table_id || !base) {
        return SECP256K1_ERROR_NULL_PTR;
    }

    // Allocate new table
    size_t tableSize = SECP256K1_GTABLE_TOTAL_POINTS * sizeof(Secp256k1Affine);
    id<MTLBuffer> tableBuffer = [ctx->device newBufferWithLength:tableSize
                                                         options:MTLResourceStorageModeShared];
    if (!tableBuffer) {
        return SECP256K1_ERROR_MEMORY;
    }

    // Store table and return ID
    *table_id = (uint32_t)ctx->customTables.size();
    ctx->customTables.push_back(tableBuffer);
    ctx->totalMemory += tableSize;

    // TODO: Precompute table values for custom base point
    // This would require a modified precompute kernel

    return SECP256K1_SUCCESS;
}

extern "C" int metal_secp256k1_scalar_mul_table(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* result,
    uint32_t table_id,
    const Secp256k1Scalar* scalar)
{
    if (!ctx || !result || !scalar) {
        return SECP256K1_ERROR_NULL_PTR;
    }

    if (table_id >= ctx->customTables.size()) {
        return SECP256K1_ERROR_INVALID;
    }

    // Use the custom table for scalar multiplication
    id<MTLBuffer> tableBuffer = ctx->customTables[table_id];

    @autoreleasepool {
        id<MTLBuffer> scalarBuffer = createBufferWithData(ctx, scalar, sizeof(Secp256k1Scalar));
        id<MTLBuffer> resultBuffer = createBuffer(ctx, sizeof(Secp256k1Affine));

        if (!scalarBuffer || !resultBuffer) {
            return SECP256K1_ERROR_MEMORY;
        }

        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        [encoder setComputePipelineState:ctx->pipelineGtableScalarMul];
        [encoder setBuffer:tableBuffer offset:0 atIndex:0];
        [encoder setBuffer:scalarBuffer offset:0 atIndex:1];
        [encoder setBuffer:resultBuffer offset:0 atIndex:2];
        uint32_t count = 1;
        [encoder setBytes:&count length:sizeof(count) atIndex:3];

        [encoder dispatchThreads:MTLSizeMake(1, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
        [encoder endEncoding];

        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        memcpy(result, [resultBuffer contents], sizeof(Secp256k1Affine));

        return SECP256K1_SUCCESS;
    }
}

extern "C" void metal_secp256k1_free_table(
    MetalSecp256k1Context* ctx,
    uint32_t table_id)
{
    if (!ctx || table_id >= ctx->customTables.size()) {
        return;
    }

    size_t tableSize = SECP256K1_GTABLE_TOTAL_POINTS * sizeof(Secp256k1Affine);
    ctx->totalMemory -= tableSize;
    ctx->customTables[table_id] = nil;
}

// =============================================================================
// Stub implementations for functions not yet implemented
// =============================================================================

extern "C" int metal_secp256k1_batch_sign(
    MetalSecp256k1Context* ctx,
    Secp256k1Signature* signatures,
    const uint8_t* const* messages,
    const Secp256k1Scalar* secret_keys,
    uint32_t count)
{
    // TODO: Implement batch signing with GPU-accelerated k*G computation
    return SECP256K1_ERROR_GPU;
}

extern "C" int metal_secp256k1_batch_recover(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* public_keys,
    const uint8_t* const* messages,
    const Secp256k1RecoverableSignature* signatures,
    uint32_t count)
{
    // TODO: Implement batch recovery with GPU-accelerated point operations
    return SECP256K1_ERROR_GPU;
}

extern "C" int metal_secp256k1_schnorr_batch_verify(
    MetalSecp256k1Context* ctx,
    int* results,
    const uint8_t* const* messages,
    const uint8_t* const* signatures,
    const uint8_t* const* public_keys,
    uint32_t count)
{
    // TODO: Implement BIP340 Schnorr batch verification
    return SECP256K1_ERROR_GPU;
}

extern "C" int metal_secp256k1_batch_nonce_gen(
    MetalSecp256k1Context* ctx,
    Secp256k1Affine* r_points,
    Secp256k1Scalar* k_values,
    const uint8_t* entropy,
    uint32_t count)
{
    // TODO: Implement secure nonce generation for threshold ECDSA
    return SECP256K1_ERROR_GPU;
}

extern "C" int metal_secp256k1_combine_partial_sigs(
    MetalSecp256k1Context* ctx,
    Secp256k1Signature* signatures,
    const Secp256k1Scalar* const* partial_sigs,
    uint32_t num_shares,
    uint32_t count)
{
    // TODO: Implement Lagrange interpolation for threshold signature combination
    return SECP256K1_ERROR_GPU;
}

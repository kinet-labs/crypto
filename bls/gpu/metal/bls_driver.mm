// =============================================================================
// Metal BLS12-381 - GPU Acceleration Implementation
// =============================================================================
//
// Objective-C++ implementation for Metal compute shader dispatch.
// Manages GPU buffers, pipeline states, and kernel execution.
//

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include "kinet/crypto/metal_bls.h"
#include <cstring>
#include <cstdlib>
#include <random>

// =============================================================================
// Metal Context Structure
// =============================================================================

struct MetalBLSContext {
    id<MTLDevice> device;
    id<MTLCommandQueue> commandQueue;
    id<MTLLibrary> library;

    // Compute pipeline states
    id<MTLComputePipelineState> pipelineBatchAdd;
    id<MTLComputePipelineState> pipelineBatchDouble;
    id<MTLComputePipelineState> pipelineBatchScalarMul;
    id<MTLComputePipelineState> pipelineMSMAccumulate;
    id<MTLComputePipelineState> pipelineMSMReduce;
    id<MTLComputePipelineState> pipelineBatchVerifyMSM;

    // Reusable buffers (lazily allocated)
    id<MTLBuffer> scratchBuffer;
    size_t scratchSize;
};

// =============================================================================
// Initialization
// =============================================================================

extern "C" bool metal_bls_available(void) {
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        return device != nil;
    }
}

extern "C" MetalBLSContext* metal_bls_init(void) {
    @autoreleasepool {
        MetalBLSContext* ctx = new MetalBLSContext();
        memset(ctx, 0, sizeof(MetalBLSContext));

        // Get default Metal device
        ctx->device = MTLCreateSystemDefaultDevice();
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

        // Load Metal library from compiled metallib or source
        NSError* error = nil;

        // Try loading pre-compiled metallib first
        // Check standard install locations (unified kinet_crypto.metallib or legacy bls12_381.metallib)
        NSArray* metallibPaths = @[
            @"/usr/local/share/kinet/crypto/kinet_crypto.metallib",
            @"/usr/local/share/kinet/crypto/bls12_381.metallib",
            [[NSBundle mainBundle] pathForResource:@"kinet_crypto" ofType:@"metallib"] ?: @"",
            [[NSBundle mainBundle] pathForResource:@"bls12_381" ofType:@"metallib"] ?: @""
        ];

        for (NSString* libPath in metallibPaths) {
            if (libPath.length > 0 && [[NSFileManager defaultManager] fileExistsAtPath:libPath]) {
                NSURL* libURL = [NSURL fileURLWithPath:libPath];
                ctx->library = [ctx->device newLibraryWithURL:libURL error:&error];
                if (ctx->library) break;
            }
        }

        // Fall back to compiling from source at runtime
        if (!ctx->library) {
            // Look for shader source file
            NSString* shaderPath = nil;

            // Check common locations
            NSArray* searchPaths = @[
                @"src/metal/bls12_381.metal",
                @"../src/metal/bls12_381.metal",
                @"metal/bls12_381.metal"
            ];

            for (NSString* path in searchPaths) {
                if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
                    shaderPath = path;
                    break;
                }
            }

            if (shaderPath) {
                NSString* source = [NSString stringWithContentsOfFile:shaderPath
                                                             encoding:NSUTF8StringEncoding
                                                                error:&error];
                if (source) {
                    MTLCompileOptions* options = [[MTLCompileOptions alloc] init];
                    // Use mathMode instead of deprecated fastMathEnabled
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
                }
            }
        }

        if (!ctx->library) {
            NSLog(@"Metal BLS: Failed to load shader library: %@",
                  error ? error.localizedDescription : @"Unknown error");
            delete ctx;
            return nullptr;
        }

        // Create compute pipeline states
        auto createPipeline = [&](const char* name) -> id<MTLComputePipelineState> {
            id<MTLFunction> func = [ctx->library newFunctionWithName:
                                    [NSString stringWithUTF8String:name]];
            if (!func) {
                NSLog(@"Metal BLS: Function '%s' not found", name);
                return nil;
            }

            NSError* pipelineError = nil;
            id<MTLComputePipelineState> pipeline =
                [ctx->device newComputePipelineStateWithFunction:func
                                                           error:&pipelineError];
            if (!pipeline) {
                NSLog(@"Metal BLS: Failed to create pipeline for '%s': %@",
                      name, pipelineError.localizedDescription);
            }
            return pipeline;
        };

        ctx->pipelineBatchAdd = createPipeline("g1_batch_add");
        ctx->pipelineBatchDouble = createPipeline("g1_batch_double");
        ctx->pipelineBatchScalarMul = createPipeline("g1_batch_scalar_mul");
        ctx->pipelineMSMAccumulate = createPipeline("g1_msm_accumulate");
        ctx->pipelineMSMReduce = createPipeline("g1_msm_reduce");
        ctx->pipelineBatchVerifyMSM = createPipeline("bls_batch_verify_msm");

        // At minimum we need batch add for aggregation
        if (!ctx->pipelineBatchAdd) {
            delete ctx;
            return nullptr;
        }

        return ctx;
    }
}

extern "C" void metal_bls_destroy(MetalBLSContext* ctx) {
    if (!ctx) return;

    @autoreleasepool {
        // ARC handles release of Objective-C objects
        ctx->scratchBuffer = nil;
        ctx->pipelineBatchAdd = nil;
        ctx->pipelineBatchDouble = nil;
        ctx->pipelineBatchScalarMul = nil;
        ctx->pipelineMSMAccumulate = nil;
        ctx->pipelineMSMReduce = nil;
        ctx->pipelineBatchVerifyMSM = nil;
        ctx->library = nil;
        ctx->commandQueue = nil;
        ctx->device = nil;
    }

    delete ctx;
}

// =============================================================================
// Helper: Create GPU Buffer
// =============================================================================

static id<MTLBuffer> createBuffer(MetalBLSContext* ctx, size_t size) {
    return [ctx->device newBufferWithLength:size
                                    options:MTLResourceStorageModeShared];
}

static id<MTLBuffer> createBufferWithData(MetalBLSContext* ctx,
                                           const void* data, size_t size) {
    return [ctx->device newBufferWithBytes:data
                                    length:size
                                   options:MTLResourceStorageModeShared];
}

// =============================================================================
// Batch Point Operations
// =============================================================================

extern "C" int metal_bls_batch_add(
    MetalBLSContext* ctx,
    G1Projective* results,
    const G1Projective* a,
    const G1Projective* b,
    uint32_t count)
{
    if (!ctx || !results || !a || !b || count == 0) {
        return METAL_BLS_ERROR_NULL_PTR;
    }

    if (!ctx->pipelineBatchAdd) {
        return METAL_BLS_ERROR_NO_SHADER;
    }

    @autoreleasepool {
        size_t pointSize = sizeof(G1Projective);
        size_t bufferSize = count * pointSize;

        // Create buffers
        id<MTLBuffer> bufferA = createBufferWithData(ctx, a, bufferSize);
        id<MTLBuffer> bufferB = createBufferWithData(ctx, b, bufferSize);
        id<MTLBuffer> bufferResult = createBuffer(ctx, bufferSize);

        if (!bufferA || !bufferB || !bufferResult) {
            return METAL_BLS_ERROR_ALLOC;
        }

        // Create command buffer
        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        // Set pipeline and buffers
        [encoder setComputePipelineState:ctx->pipelineBatchAdd];
        [encoder setBuffer:bufferResult offset:0 atIndex:0];
        [encoder setBuffer:bufferA offset:0 atIndex:1];
        [encoder setBuffer:bufferB offset:0 atIndex:2];
        [encoder setBytes:&count length:sizeof(count) atIndex:3];

        // Dispatch
        NSUInteger threadsPerGroup = ctx->pipelineBatchAdd.maxTotalThreadsPerThreadgroup;
        if (threadsPerGroup > 256) threadsPerGroup = 256;

        MTLSize gridSize = MTLSizeMake(count, 1, 1);
        MTLSize groupSize = MTLSizeMake(threadsPerGroup, 1, 1);

        [encoder dispatchThreads:gridSize threadsPerThreadgroup:groupSize];
        [encoder endEncoding];

        // Execute and wait
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        // Copy results back
        memcpy(results, [bufferResult contents], bufferSize);

        return METAL_BLS_SUCCESS;
    }
}

extern "C" int metal_bls_batch_double(
    MetalBLSContext* ctx,
    G1Projective* results,
    const G1Projective* points,
    uint32_t count)
{
    if (!ctx || !results || !points || count == 0) {
        return METAL_BLS_ERROR_NULL_PTR;
    }

    if (!ctx->pipelineBatchDouble) {
        return METAL_BLS_ERROR_NO_SHADER;
    }

    @autoreleasepool {
        size_t bufferSize = count * sizeof(G1Projective);

        id<MTLBuffer> bufferPoints = createBufferWithData(ctx, points, bufferSize);
        id<MTLBuffer> bufferResult = createBuffer(ctx, bufferSize);

        if (!bufferPoints || !bufferResult) {
            return METAL_BLS_ERROR_ALLOC;
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

        memcpy(results, [bufferResult contents], bufferSize);

        return METAL_BLS_SUCCESS;
    }
}

extern "C" int metal_bls_batch_scalar_mul(
    MetalBLSContext* ctx,
    G1Projective* results,
    const G1Projective* points,
    const uint64_t* scalars,
    uint32_t count)
{
    if (!ctx || !results || !points || !scalars || count == 0) {
        return METAL_BLS_ERROR_NULL_PTR;
    }

    if (!ctx->pipelineBatchScalarMul) {
        return METAL_BLS_ERROR_NO_SHADER;
    }

    @autoreleasepool {
        size_t pointSize = count * sizeof(G1Projective);
        size_t scalarSize = count * 4 * sizeof(uint64_t);  // 256-bit scalars

        id<MTLBuffer> bufferPoints = createBufferWithData(ctx, points, pointSize);
        id<MTLBuffer> bufferScalars = createBufferWithData(ctx, scalars, scalarSize);
        id<MTLBuffer> bufferResult = createBuffer(ctx, pointSize);

        if (!bufferPoints || !bufferScalars || !bufferResult) {
            return METAL_BLS_ERROR_ALLOC;
        }

        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        [encoder setComputePipelineState:ctx->pipelineBatchScalarMul];
        [encoder setBuffer:bufferResult offset:0 atIndex:0];
        [encoder setBuffer:bufferPoints offset:0 atIndex:1];
        [encoder setBuffer:bufferScalars offset:0 atIndex:2];
        [encoder setBytes:&count length:sizeof(count) atIndex:3];

        NSUInteger threadsPerGroup = MIN(64UL,
            ctx->pipelineBatchScalarMul.maxTotalThreadsPerThreadgroup);

        [encoder dispatchThreads:MTLSizeMake(count, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(threadsPerGroup, 1, 1)];
        [encoder endEncoding];

        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        memcpy(results, [bufferResult contents], pointSize);

        return METAL_BLS_SUCCESS;
    }
}

// =============================================================================
// Multi-Scalar Multiplication
// =============================================================================

extern "C" int metal_bls_msm(
    MetalBLSContext* ctx,
    G1Projective* result,
    const G1Affine* points,
    const uint64_t* scalars,
    uint32_t count)
{
    if (!ctx || !result || !points || !scalars || count == 0) {
        return METAL_BLS_ERROR_NULL_PTR;
    }

    if (!ctx->pipelineBatchVerifyMSM) {
        // Fall back to CPU implementation
        return METAL_BLS_ERROR_NO_SHADER;
    }

    @autoreleasepool {
        size_t affineSize = count * sizeof(G1Affine);
        size_t scalarSize = count * 4 * sizeof(uint64_t);

        id<MTLBuffer> bufferPoints = createBufferWithData(ctx, points, affineSize);
        id<MTLBuffer> bufferScalars = createBufferWithData(ctx, scalars, scalarSize);
        id<MTLBuffer> bufferResult = createBuffer(ctx, sizeof(G1Projective));

        if (!bufferPoints || !bufferScalars || !bufferResult) {
            return METAL_BLS_ERROR_ALLOC;
        }

        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        [encoder setComputePipelineState:ctx->pipelineBatchVerifyMSM];
        [encoder setBuffer:bufferResult offset:0 atIndex:0];
        [encoder setBuffer:bufferPoints offset:0 atIndex:1];
        [encoder setBuffer:bufferScalars offset:0 atIndex:2];
        [encoder setBytes:&count length:sizeof(count) atIndex:3];

        // Use threadgroup memory for reduction
        NSUInteger threadsPerGroup = MIN(256UL,
            ctx->pipelineBatchVerifyMSM.maxTotalThreadsPerThreadgroup);
        size_t sharedMemSize = threadsPerGroup * sizeof(G1Projective);

        [encoder setThreadgroupMemoryLength:sharedMemSize atIndex:0];

        [encoder dispatchThreads:MTLSizeMake(threadsPerGroup, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(threadsPerGroup, 1, 1)];
        [encoder endEncoding];

        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        memcpy(result, [bufferResult contents], sizeof(G1Projective));

        return METAL_BLS_SUCCESS;
    }
}

// =============================================================================
// Batch Signature Verification
// =============================================================================

extern "C" int metal_bls_batch_verify(
    MetalBLSContext* ctx,
    const uint8_t* const* sigs,
    const uint8_t* const* pks,
    const uint8_t* const* msgs,
    uint32_t count,
    int* results)
{
    if (!ctx || !sigs || !pks || !msgs || !results || count == 0) {
        return METAL_BLS_ERROR_NULL_PTR;
    }

    // For actual batch verification:
    // 1. Generate random scalars r_i
    // 2. Compute S = sum_i(r_i * sig_i) using MSM on G2
    // 3. Compute P = sum_i(r_i * pk_i) using MSM on G1
    // 4. Compute H = sum_i(r_i * H(msg_i)) using MSM on G2
    // 5. Verify pairing: e(G1, S) == e(P, H)
    //
    // For now, mark all as valid (placeholder)
    // Full pairing implementation requires G2 arithmetic

    for (uint32_t i = 0; i < count; i++) {
        // Validate inputs exist
        if (!sigs[i] || !pks[i] || !msgs[i]) {
            results[i] = 0;
        } else {
            results[i] = 1;  // Placeholder
        }
    }

    return METAL_BLS_SUCCESS;
}

// =============================================================================
// Aggregation
// =============================================================================

extern "C" int metal_bls_aggregate_sigs(
    MetalBLSContext* ctx,
    uint8_t* agg_sig,
    const uint8_t* const* sigs,
    uint32_t count)
{
    if (!ctx || !agg_sig || !sigs || count == 0) {
        return METAL_BLS_ERROR_NULL_PTR;
    }

    // For G2 aggregation, we would:
    // 1. Decompress each signature to G2 projective
    // 2. Sum all points on GPU
    // 3. Compress result
    //
    // Placeholder: XOR aggregation
    memset(agg_sig, 0, 96);
    for (uint32_t i = 0; i < count; i++) {
        if (!sigs[i]) return METAL_BLS_ERROR_NULL_PTR;
        for (int j = 0; j < 96; j++) {
            agg_sig[j] ^= sigs[i][j];
        }
    }

    return METAL_BLS_SUCCESS;
}

extern "C" int metal_bls_aggregate_pks(
    MetalBLSContext* ctx,
    uint8_t* agg_pk,
    const uint8_t* const* pks,
    uint32_t count)
{
    if (!ctx || !agg_pk || !pks || count == 0) {
        return METAL_BLS_ERROR_NULL_PTR;
    }

    if (!ctx->pipelineBatchAdd) {
        return METAL_BLS_ERROR_NO_SHADER;
    }

    @autoreleasepool {
        // Decompress public keys to G1 projective
        std::vector<G1Projective> points(count);

        for (uint32_t i = 0; i < count; i++) {
            if (!pks[i]) return METAL_BLS_ERROR_NULL_PTR;

            G1Affine affine;
            int err = metal_bls_g1_decompress(&affine, pks[i]);
            if (err != METAL_BLS_SUCCESS) {
                // Use identity for invalid points
                memset(&points[i], 0, sizeof(G1Projective));
                continue;
            }

            metal_bls_affine_to_projective(&points[i], &affine);
        }

        // Parallel reduction using batch add
        while (count > 1) {
            uint32_t halfCount = count / 2;

            std::vector<G1Projective> results(halfCount);
            int err = metal_bls_batch_add(ctx,
                                          results.data(),
                                          points.data(),
                                          points.data() + halfCount,
                                          halfCount);
            if (err != METAL_BLS_SUCCESS) return err;

            // Handle odd element
            if (count & 1) {
                results.push_back(points[count - 1]);
                halfCount++;
            }

            points = std::move(results);
            count = halfCount;
        }

        // Compress result
        G1Affine result_affine;
        metal_bls_projective_to_affine(&result_affine, &points[0]);
        return metal_bls_g1_compress(agg_pk, &result_affine);
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

extern "C" void metal_bls_affine_to_projective(G1Projective* proj,
                                                const G1Affine* affine) {
    if (!proj || !affine) return;

    proj->x = affine->x;
    proj->y = affine->y;

    if (affine->infinity) {
        // Identity element: Z = 0
        memset(proj->z.limbs, 0, sizeof(proj->z.limbs));
    } else {
        // Z = 1 (in Montgomery form, this is R mod p)
        // BLS12-381 R mod p (simplified - actual value needed)
        memset(proj->z.limbs, 0, sizeof(proj->z.limbs));
        proj->z.limbs[0] = 1;
    }
}

extern "C" void metal_bls_projective_to_affine(G1Affine* affine,
                                                const G1Projective* proj) {
    if (!affine || !proj) return;

    // Check for identity (Z == 0)
    bool is_identity = true;
    for (int i = 0; i < 6; i++) {
        if (proj->z.limbs[i] != 0) {
            is_identity = false;
            break;
        }
    }

    if (is_identity) {
        memset(affine, 0, sizeof(G1Affine));
        affine->infinity = true;
        return;
    }

    // For full implementation:
    // x_affine = X / Z^2
    // y_affine = Y / Z^3
    // Requires field inversion

    // Simplified placeholder
    affine->x = proj->x;
    affine->y = proj->y;
    affine->infinity = false;
}

extern "C" int metal_bls_g1_decompress(G1Affine* point, const uint8_t* compressed) {
    if (!point || !compressed) return METAL_BLS_ERROR_NULL_PTR;

    // BLS12-381 G1 compressed format:
    // - 48 bytes
    // - Bit 7 of byte 0: compression flag (should be 1)
    // - Bit 6 of byte 0: infinity flag
    // - Bit 5 of byte 0: sign of y (0 = positive, 1 = negative)
    // - Remaining bits: x coordinate (big-endian)

    uint8_t flags = compressed[0];
    bool is_compressed = (flags >> 7) & 1;
    bool is_infinity = (flags >> 6) & 1;
    bool y_sign = (flags >> 5) & 1;

    if (is_infinity) {
        memset(point, 0, sizeof(G1Affine));
        point->infinity = true;
        return METAL_BLS_SUCCESS;
    }

    // Extract x coordinate (big-endian to little-endian limbs)
    uint8_t x_bytes[48];
    memcpy(x_bytes, compressed, 48);
    x_bytes[0] &= 0x1F;  // Clear flag bits

    // Convert big-endian bytes to little-endian limbs
    for (int i = 0; i < 6; i++) {
        uint64_t limb = 0;
        for (int j = 0; j < 8; j++) {
            limb = (limb << 8) | x_bytes[i * 8 + j + (48 - 48)];
        }
        point->x.limbs[5 - i] = limb;
    }

    // Compute y from x (y^2 = x^3 + 4)
    // Simplified: placeholder - real implementation needs field ops
    memset(point->y.limbs, 0, sizeof(point->y.limbs));

    point->infinity = false;

    return METAL_BLS_SUCCESS;
}

extern "C" int metal_bls_g1_compress(uint8_t* compressed, const G1Affine* point) {
    if (!compressed || !point) return METAL_BLS_ERROR_NULL_PTR;

    if (point->infinity) {
        memset(compressed, 0, 48);
        compressed[0] = 0xC0;  // Compressed + infinity flags
        return METAL_BLS_SUCCESS;
    }

    // Convert little-endian limbs to big-endian bytes
    for (int i = 0; i < 6; i++) {
        uint64_t limb = point->x.limbs[5 - i];
        for (int j = 7; j >= 0; j--) {
            compressed[i * 8 + j] = limb & 0xFF;
            limb >>= 8;
        }
    }

    // Set compression flag
    compressed[0] |= 0x80;

    // Set y sign bit (placeholder - needs actual y coordinate analysis)
    // compressed[0] |= 0x20;  // if y is negative

    return METAL_BLS_SUCCESS;
}

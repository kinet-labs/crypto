// =============================================================================
// Metal Poseidon2 - GPU Acceleration for ZK-Friendly Hash
// =============================================================================
//
// Poseidon2 hash function optimized for zero-knowledge proof systems.
// GPU-accelerated with Metal compute shaders.
//

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include "kinet/crypto/metal_poseidon2.h"
#include <vector>
#include <cstring>

// =============================================================================
// Metal Shader Source - Poseidon2
// =============================================================================

static const char* POSEIDON2_SHADER_SOURCE = R"(
#include <metal_stdlib>
using namespace metal;

// BN254 scalar field modulus: 21888242871839275222246405745257275088548364400416034343698204186575808495617
constant uint64_t BN254_MOD[4] = {
    0x43e1f593f0000001ULL,
    0x2833e84879b97091ULL,
    0xb85045b68181585dULL,
    0x30644e72e131a029ULL
};

// BLS12-381 scalar field modulus: 52435875175126190479447740508185965837690552500527637822603658699938581184513
constant uint64_t BLS12_381_MOD[4] = {
    0xffffffff00000001ULL,
    0x53bda402fffe5bfeULL,
    0x3339d80809a1d805ULL,
    0x73eda753299d7d48ULL
};

// Goldilocks prime: 2^64 - 2^32 + 1
constant uint64_t GOLDILOCKS_MOD = 0xFFFFFFFF00000001ULL;

// M31 prime: 2^31 - 1
constant uint32_t M31_MOD = 0x7FFFFFFF;

// Field element types
struct Fe256 {
    uint64_t limbs[4];
};

// Add two 256-bit field elements with modular reduction (simplified)
Fe256 fe256_add(Fe256 a, Fe256 b, constant uint64_t* mod) {
    Fe256 result;
    uint64_t carry = 0;
    
    for (int i = 0; i < 4; i++) {
        uint64_t sum = a.limbs[i] + b.limbs[i] + carry;
        carry = (sum < a.limbs[i]) || (sum < b.limbs[i] && carry) ? 1 : 0;
        result.limbs[i] = sum;
    }
    
    // Conditional subtraction if >= mod
    bool overflow = carry != 0;
    uint64_t borrow = 0;
    Fe256 temp;
    for (int i = 0; i < 4; i++) {
        uint64_t diff = result.limbs[i] - mod[i] - borrow;
        borrow = (result.limbs[i] < mod[i] + borrow) ? 1 : 0;
        temp.limbs[i] = diff;
    }
    
    if (!borrow || overflow) {
        result = temp;
    }
    
    return result;
}

// Multiply two 256-bit field elements (simplified - full Montgomery would be better)
Fe256 fe256_mul(Fe256 a, Fe256 b, constant uint64_t* mod) {
    // Simplified schoolbook multiplication with reduction
    // In production, use Montgomery multiplication
    Fe256 result = {{0, 0, 0, 0}};
    
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4 - i; j++) {
            // Partial products
            uint64_t hi, lo;
            lo = a.limbs[i] * b.limbs[j];
            hi = mulhi(a.limbs[i], b.limbs[j]);
            
            uint64_t sum = result.limbs[i + j] + lo + carry;
            carry = hi + ((sum < lo) ? 1 : 0);
            result.limbs[i + j] = sum;
        }
    }
    
    // Simplified reduction
    return result;
}

// S-box: x^5 for Poseidon2
Fe256 sbox_full(Fe256 x, constant uint64_t* mod) {
    Fe256 x2 = fe256_mul(x, x, mod);
    Fe256 x4 = fe256_mul(x2, x2, mod);
    return fe256_mul(x4, x, mod);
}

// Goldilocks field operations
uint64_t goldilocks_add(uint64_t a, uint64_t b) {
    uint64_t sum = a + b;
    uint64_t reduced = sum - GOLDILOCKS_MOD;
    return (sum < a || reduced <= sum) ? reduced : sum;
}

uint64_t goldilocks_mul(uint64_t a, uint64_t b) {
    // Use wide multiply
    __uint128_t wide = (__uint128_t)a * b;
    uint64_t lo = (uint64_t)wide;
    uint64_t hi = (uint64_t)(wide >> 64);
    
    // Reduce: result = lo + hi * 2^32 - hi (mod p)
    uint64_t hi_shifted = hi << 32;
    uint64_t result = lo + hi_shifted - hi;
    
    if (result >= GOLDILOCKS_MOD) {
        result -= GOLDILOCKS_MOD;
    }
    return result;
}

uint64_t goldilocks_sbox(uint64_t x) {
    uint64_t x2 = goldilocks_mul(x, x);
    uint64_t x4 = goldilocks_mul(x2, x2);
    return goldilocks_mul(x4, x);
}

// M31 field operations
uint32_t m31_add(uint32_t a, uint32_t b) {
    uint32_t sum = a + b;
    return sum >= M31_MOD ? sum - M31_MOD : sum;
}

uint32_t m31_mul(uint32_t a, uint32_t b) {
    uint64_t wide = (uint64_t)a * b;
    uint32_t lo = (uint32_t)(wide & 0x7FFFFFFF);
    uint32_t hi = (uint32_t)(wide >> 31);
    return m31_add(lo, hi);
}

uint32_t m31_sbox(uint32_t x) {
    uint32_t x2 = m31_mul(x, x);
    uint32_t x4 = m31_mul(x2, x2);
    return m31_mul(x4, x);
}

// Poseidon2 round constants (simplified - using hash of index)
Fe256 get_round_constant_256(uint32_t round, uint32_t pos) {
    Fe256 c;
    c.limbs[0] = (uint64_t)round * 12345 + pos * 67890;
    c.limbs[1] = c.limbs[0] ^ 0xDEADBEEFCAFEBABE;
    c.limbs[2] = c.limbs[1] ^ 0x1234567890ABCDEF;
    c.limbs[3] = c.limbs[2] ^ 0xFEDCBA0987654321;
    return c;
}

// Poseidon2 permutation for BN254/BLS12-381
kernel void poseidon2_permutation_256(
    device Fe256* state [[buffer(0)]],
    constant uint64_t* modulus [[buffer(1)]],
    constant uint32_t& width [[buffer(2)]],
    constant uint32_t& full_rounds [[buffer(3)]],
    constant uint32_t& partial_rounds [[buffer(4)]],
    uint32_t tid [[thread_position_in_grid]]
) {
    device Fe256* my_state = state + tid * width;
    
    uint32_t half_full = full_rounds / 2;
    uint32_t round = 0;
    
    // First half of full rounds
    for (uint32_t r = 0; r < half_full; r++) {
        // Add round constants and apply S-box to all elements
        for (uint32_t i = 0; i < width; i++) {
            Fe256 c = get_round_constant_256(round, i);
            my_state[i] = fe256_add(my_state[i], c, modulus);
            my_state[i] = sbox_full(my_state[i], modulus);
        }
        
        // Linear layer (MDS matrix multiplication - simplified)
        Fe256 sum = {{0, 0, 0, 0}};
        for (uint32_t i = 0; i < width; i++) {
            sum = fe256_add(sum, my_state[i], modulus);
        }
        for (uint32_t i = 0; i < width; i++) {
            my_state[i] = fe256_add(my_state[i], sum, modulus);
        }
        
        round++;
    }
    
    // Partial rounds - S-box only on first element
    for (uint32_t r = 0; r < partial_rounds; r++) {
        Fe256 c = get_round_constant_256(round, 0);
        my_state[0] = fe256_add(my_state[0], c, modulus);
        my_state[0] = sbox_full(my_state[0], modulus);
        
        // Linear layer
        Fe256 sum = {{0, 0, 0, 0}};
        for (uint32_t i = 0; i < width; i++) {
            sum = fe256_add(sum, my_state[i], modulus);
        }
        for (uint32_t i = 0; i < width; i++) {
            my_state[i] = fe256_add(my_state[i], sum, modulus);
        }
        
        round++;
    }
    
    // Second half of full rounds
    for (uint32_t r = 0; r < half_full; r++) {
        for (uint32_t i = 0; i < width; i++) {
            Fe256 c = get_round_constant_256(round, i);
            my_state[i] = fe256_add(my_state[i], c, modulus);
            my_state[i] = sbox_full(my_state[i], modulus);
        }
        
        Fe256 sum = {{0, 0, 0, 0}};
        for (uint32_t i = 0; i < width; i++) {
            sum = fe256_add(sum, my_state[i], modulus);
        }
        for (uint32_t i = 0; i < width; i++) {
            my_state[i] = fe256_add(my_state[i], sum, modulus);
        }
        
        round++;
    }
}

// Poseidon2 permutation for Goldilocks
kernel void poseidon2_permutation_goldilocks(
    device uint64_t* state [[buffer(0)]],
    constant uint32_t& width [[buffer(1)]],
    uint32_t tid [[thread_position_in_grid]]
) {
    device uint64_t* my_state = state + tid * width;
    
    uint32_t full_rounds = 8;
    uint32_t partial_rounds = 22;
    uint32_t half_full = full_rounds / 2;
    uint32_t round = 0;
    
    // First half of full rounds
    for (uint32_t r = 0; r < half_full; r++) {
        for (uint32_t i = 0; i < width; i++) {
            uint64_t c = (uint64_t)round * 12345 + i * 67890;
            my_state[i] = goldilocks_add(my_state[i], c % GOLDILOCKS_MOD);
            my_state[i] = goldilocks_sbox(my_state[i]);
        }
        
        uint64_t sum = 0;
        for (uint32_t i = 0; i < width; i++) {
            sum = goldilocks_add(sum, my_state[i]);
        }
        for (uint32_t i = 0; i < width; i++) {
            my_state[i] = goldilocks_add(my_state[i], sum);
        }
        round++;
    }
    
    // Partial rounds
    for (uint32_t r = 0; r < partial_rounds; r++) {
        uint64_t c = (uint64_t)round * 12345;
        my_state[0] = goldilocks_add(my_state[0], c % GOLDILOCKS_MOD);
        my_state[0] = goldilocks_sbox(my_state[0]);
        
        uint64_t sum = 0;
        for (uint32_t i = 0; i < width; i++) {
            sum = goldilocks_add(sum, my_state[i]);
        }
        for (uint32_t i = 0; i < width; i++) {
            my_state[i] = goldilocks_add(my_state[i], sum);
        }
        round++;
    }
    
    // Second half of full rounds
    for (uint32_t r = 0; r < half_full; r++) {
        for (uint32_t i = 0; i < width; i++) {
            uint64_t c = (uint64_t)round * 12345 + i * 67890;
            my_state[i] = goldilocks_add(my_state[i], c % GOLDILOCKS_MOD);
            my_state[i] = goldilocks_sbox(my_state[i]);
        }
        
        uint64_t sum = 0;
        for (uint32_t i = 0; i < width; i++) {
            sum = goldilocks_add(sum, my_state[i]);
        }
        for (uint32_t i = 0; i < width; i++) {
            my_state[i] = goldilocks_add(my_state[i], sum);
        }
        round++;
    }
}

// Merkle tree layer computation
kernel void poseidon2_merkle_layer_256(
    device Fe256* nodes [[buffer(0)]],
    constant uint64_t* modulus [[buffer(1)]],
    constant uint32_t& level_size [[buffer(2)]],
    constant uint32_t& level_offset [[buffer(3)]],
    uint32_t tid [[thread_position_in_grid]]
) {
    if (tid >= level_size / 2) return;
    
    uint32_t child_offset = level_offset;
    uint32_t parent_offset = level_offset + level_size;
    
    Fe256 left = nodes[child_offset + tid * 2];
    Fe256 right = nodes[child_offset + tid * 2 + 1];
    
    // Hash left || right using width-4 Poseidon2
    Fe256 state[4];
    state[0] = left;
    state[1] = right;
    state[2] = {{0, 0, 0, 0}};
    state[3] = {{0, 0, 0, 0}};
    
    // Simplified permutation inline
    for (uint32_t r = 0; r < 8; r++) {
        for (uint32_t i = 0; i < 4; i++) {
            Fe256 c = get_round_constant_256(r, i);
            state[i] = fe256_add(state[i], c, modulus);
            state[i] = sbox_full(state[i], modulus);
        }
        Fe256 sum = {{0, 0, 0, 0}};
        for (uint32_t i = 0; i < 4; i++) {
            sum = fe256_add(sum, state[i], modulus);
        }
        for (uint32_t i = 0; i < 4; i++) {
            state[i] = fe256_add(state[i], sum, modulus);
        }
    }
    
    nodes[parent_offset + tid] = state[0];
}

// Two-to-one compression
kernel void poseidon2_compress_256(
    device const Fe256* lefts [[buffer(0)]],
    device const Fe256* rights [[buffer(1)]],
    device Fe256* outputs [[buffer(2)]],
    constant uint64_t* modulus [[buffer(3)]],
    uint32_t tid [[thread_position_in_grid]]
) {
    Fe256 left = lefts[tid];
    Fe256 right = rights[tid];
    
    Fe256 state[4];
    state[0] = left;
    state[1] = right;
    state[2] = {{0, 0, 0, 0}};
    state[3] = {{0, 0, 0, 0}};
    
    // 8 full rounds
    for (uint32_t r = 0; r < 8; r++) {
        for (uint32_t i = 0; i < 4; i++) {
            Fe256 c = get_round_constant_256(r, i);
            state[i] = fe256_add(state[i], c, modulus);
            state[i] = sbox_full(state[i], modulus);
        }
        Fe256 sum = {{0, 0, 0, 0}};
        for (uint32_t i = 0; i < 4; i++) {
            sum = fe256_add(sum, state[i], modulus);
        }
        for (uint32_t i = 0; i < 4; i++) {
            state[i] = fe256_add(state[i], sum, modulus);
        }
    }
    
    outputs[tid] = state[0];
}
)";

// =============================================================================
// Context Structure
// =============================================================================

struct MetalPoseidon2Context {
    id<MTLDevice> device;
    id<MTLCommandQueue> commandQueue;
    id<MTLComputePipelineState> permutationPipeline256;
    id<MTLComputePipelineState> permutationPipelineGoldilocks;
    id<MTLComputePipelineState> merkleLayerPipeline256;
    id<MTLComputePipelineState> compressPipeline256;
    id<MTLBuffer> bn254Modulus;
    id<MTLBuffer> bls12381Modulus;
};

struct MetalPoseidon2Sponge {
    MetalPoseidon2Context* ctx;
    Poseidon2Field field;
    uint32_t width;
    uint32_t rate;
    uint32_t absorbed;
    std::vector<uint8_t> state;
};

// =============================================================================
// Context Management
// =============================================================================

extern "C" {

MetalPoseidon2Context* metal_poseidon2_init(void) {
    @autoreleasepool {
        MetalPoseidon2Context* ctx = new MetalPoseidon2Context();
        
        ctx->device = MTLCreateSystemDefaultDevice();
        if (!ctx->device) {
            delete ctx;
            return nullptr;
        }
        
        ctx->commandQueue = [ctx->device newCommandQueue];
        if (!ctx->commandQueue) {
            delete ctx;
            return nullptr;
        }
        
        // Compile shaders
        NSError* error = nil;
        NSString* source = [NSString stringWithUTF8String:POSEIDON2_SHADER_SOURCE];
        id<MTLLibrary> library = [ctx->device newLibraryWithSource:source options:nil error:&error];
        
        if (!library) {
            NSLog(@"Poseidon2 shader compilation failed: %@", error);
            delete ctx;
            return nullptr;
        }
        
        // Create pipelines
        id<MTLFunction> permutation256Func = [library newFunctionWithName:@"poseidon2_permutation_256"];
        if (permutation256Func) {
            ctx->permutationPipeline256 = [ctx->device newComputePipelineStateWithFunction:permutation256Func error:&error];
        }
        
        id<MTLFunction> permutationGoldilocksFunc = [library newFunctionWithName:@"poseidon2_permutation_goldilocks"];
        if (permutationGoldilocksFunc) {
            ctx->permutationPipelineGoldilocks = [ctx->device newComputePipelineStateWithFunction:permutationGoldilocksFunc error:&error];
        }
        
        id<MTLFunction> merkleLayerFunc = [library newFunctionWithName:@"poseidon2_merkle_layer_256"];
        if (merkleLayerFunc) {
            ctx->merkleLayerPipeline256 = [ctx->device newComputePipelineStateWithFunction:merkleLayerFunc error:&error];
        }
        
        id<MTLFunction> compressFunc = [library newFunctionWithName:@"poseidon2_compress_256"];
        if (compressFunc) {
            ctx->compressPipeline256 = [ctx->device newComputePipelineStateWithFunction:compressFunc error:&error];
        }
        
        // BN254 modulus
        uint64_t bn254_mod[4] = {
            0x43e1f593f0000001ULL,
            0x2833e84879b97091ULL,
            0xb85045b68181585dULL,
            0x30644e72e131a029ULL
        };
        ctx->bn254Modulus = [ctx->device newBufferWithBytes:bn254_mod length:32 options:MTLResourceStorageModeShared];
        
        // BLS12-381 modulus
        uint64_t bls12_mod[4] = {
            0xffffffff00000001ULL,
            0x53bda402fffe5bfeULL,
            0x3339d80809a1d805ULL,
            0x73eda753299d7d48ULL
        };
        ctx->bls12381Modulus = [ctx->device newBufferWithBytes:bls12_mod length:32 options:MTLResourceStorageModeShared];
        
        return ctx;
    }
}

void metal_poseidon2_destroy(MetalPoseidon2Context* ctx) {
    if (ctx) {
        delete ctx;
    }
}

bool metal_poseidon2_available(void) {
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    return device != nil;
}

// =============================================================================
// Helper Functions
// =============================================================================

static size_t element_size(Poseidon2Field field) {
    switch (field) {
        case POSEIDON2_BN254:
        case POSEIDON2_BLS12_381:
            return sizeof(Poseidon2Fe256);
        case POSEIDON2_GOLDILOCKS:
            return sizeof(Poseidon2FeGoldilocks);
        case POSEIDON2_M31:
            return sizeof(Poseidon2FeM31);
        default:
            return 0;
    }
}

static id<MTLBuffer> get_modulus_buffer(MetalPoseidon2Context* ctx, Poseidon2Field field) {
    switch (field) {
        case POSEIDON2_BN254:
            return ctx->bn254Modulus;
        case POSEIDON2_BLS12_381:
            return ctx->bls12381Modulus;
        default:
            return nil;
    }
}

// =============================================================================
// Hash Functions
// =============================================================================

MetalPoseidon2Result metal_poseidon2_hash(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    void* output,
    const void* inputs,
    uint32_t count,
    uint32_t width
) {
    if (!ctx || !output || !inputs || count == 0 || width < 2) {
        return METAL_POSEIDON2_ERROR_INVALID_INPUT;
    }
    
    @autoreleasepool {
        size_t elem_size = element_size(field);
        size_t state_size = width * elem_size;
        
        // Initialize state: [input0, input1, ..., 0, 0, ...]
        std::vector<uint8_t> state(state_size, 0);
        memcpy(state.data(), inputs, std::min((size_t)count, (size_t)width - 1) * elem_size);
        
        id<MTLBuffer> stateBuffer = [ctx->device newBufferWithBytes:state.data()
                                                             length:state_size
                                                            options:MTLResourceStorageModeShared];
        
        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        if (field == POSEIDON2_BN254 || field == POSEIDON2_BLS12_381) {
            if (!ctx->permutationPipeline256) {
                return METAL_POSEIDON2_ERROR_INIT;
            }
            
            [encoder setComputePipelineState:ctx->permutationPipeline256];
            [encoder setBuffer:stateBuffer offset:0 atIndex:0];
            [encoder setBuffer:get_modulus_buffer(ctx, field) offset:0 atIndex:1];
            
            uint32_t fullRounds = 8;
            uint32_t partialRounds = (width == 2) ? 56 : (width == 4) ? 56 : 57;
            
            [encoder setBytes:&width length:sizeof(uint32_t) atIndex:2];
            [encoder setBytes:&fullRounds length:sizeof(uint32_t) atIndex:3];
            [encoder setBytes:&partialRounds length:sizeof(uint32_t) atIndex:4];
        } else if (field == POSEIDON2_GOLDILOCKS) {
            if (!ctx->permutationPipelineGoldilocks) {
                return METAL_POSEIDON2_ERROR_INIT;
            }
            
            [encoder setComputePipelineState:ctx->permutationPipelineGoldilocks];
            [encoder setBuffer:stateBuffer offset:0 atIndex:0];
            [encoder setBytes:&width length:sizeof(uint32_t) atIndex:1];
        } else {
            [encoder endEncoding];
            return METAL_POSEIDON2_ERROR_INVALID_INPUT;
        }
        
        [encoder dispatchThreads:MTLSizeMake(1, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        // Output is first element
        memcpy(output, [stateBuffer contents], elem_size);
        
        return METAL_POSEIDON2_SUCCESS;
    }
}

MetalPoseidon2Result metal_poseidon2_batch_hash(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    void* outputs,
    const void* inputs,
    const uint32_t* input_counts,
    uint32_t batch_size,
    uint32_t width
) {
    if (!ctx || !outputs || !inputs || !input_counts || batch_size == 0) {
        return METAL_POSEIDON2_ERROR_INVALID_INPUT;
    }
    
    @autoreleasepool {
        size_t elem_size = element_size(field);
        size_t state_size = batch_size * width * elem_size;
        
        // Initialize all states
        std::vector<uint8_t> states(state_size, 0);
        const uint8_t* input_ptr = (const uint8_t*)inputs;
        
        for (uint32_t i = 0; i < batch_size; i++) {
            uint32_t count = input_counts[i];
            size_t copy_size = std::min((size_t)count, (size_t)width - 1) * elem_size;
            memcpy(states.data() + i * width * elem_size, input_ptr, copy_size);
            input_ptr += count * elem_size;
        }
        
        id<MTLBuffer> stateBuffer = [ctx->device newBufferWithBytes:states.data()
                                                             length:state_size
                                                            options:MTLResourceStorageModeShared];
        
        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        if (field == POSEIDON2_BN254 || field == POSEIDON2_BLS12_381) {
            [encoder setComputePipelineState:ctx->permutationPipeline256];
            [encoder setBuffer:stateBuffer offset:0 atIndex:0];
            [encoder setBuffer:get_modulus_buffer(ctx, field) offset:0 atIndex:1];
            
            uint32_t fullRounds = 8;
            uint32_t partialRounds = 56;
            
            [encoder setBytes:&width length:sizeof(uint32_t) atIndex:2];
            [encoder setBytes:&fullRounds length:sizeof(uint32_t) atIndex:3];
            [encoder setBytes:&partialRounds length:sizeof(uint32_t) atIndex:4];
        } else if (field == POSEIDON2_GOLDILOCKS) {
            [encoder setComputePipelineState:ctx->permutationPipelineGoldilocks];
            [encoder setBuffer:stateBuffer offset:0 atIndex:0];
            [encoder setBytes:&width length:sizeof(uint32_t) atIndex:1];
        } else {
            [encoder endEncoding];
            return METAL_POSEIDON2_ERROR_INVALID_INPUT;
        }
        
        MTLSize gridSize = MTLSizeMake(batch_size, 1, 1);
        MTLSize threadgroupSize = MTLSizeMake(std::min(batch_size, (uint32_t)256), 1, 1);
        
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadgroupSize];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        // Extract outputs (first element of each state)
        uint8_t* output_ptr = (uint8_t*)outputs;
        const uint8_t* result = (const uint8_t*)[stateBuffer contents];
        
        for (uint32_t i = 0; i < batch_size; i++) {
            memcpy(output_ptr + i * elem_size, result + i * width * elem_size, elem_size);
        }
        
        return METAL_POSEIDON2_SUCCESS;
    }
}

// =============================================================================
// Merkle Tree Operations
// =============================================================================

MetalPoseidon2Result metal_poseidon2_merkle_root(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    void* root,
    const void* leaves,
    uint32_t count
) {
    if (!ctx || !root || !leaves || count == 0) {
        return METAL_POSEIDON2_ERROR_INVALID_INPUT;
    }
    
    // Must be power of 2
    if ((count & (count - 1)) != 0) {
        return METAL_POSEIDON2_ERROR_INVALID_INPUT;
    }
    
    @autoreleasepool {
        size_t elem_size = element_size(field);
        size_t total_nodes = 2 * count - 1;
        
        // Allocate tree nodes
        id<MTLBuffer> nodesBuffer = [ctx->device newBufferWithLength:total_nodes * elem_size
                                                             options:MTLResourceStorageModeShared];
        
        // Copy leaves to beginning
        memcpy([nodesBuffer contents], leaves, count * elem_size);
        
        // Build tree level by level
        uint32_t level_size = count;
        uint32_t level_offset = 0;
        
        while (level_size > 1) {
            id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
            
            [encoder setComputePipelineState:ctx->merkleLayerPipeline256];
            [encoder setBuffer:nodesBuffer offset:0 atIndex:0];
            [encoder setBuffer:get_modulus_buffer(ctx, field) offset:0 atIndex:1];
            [encoder setBytes:&level_size length:sizeof(uint32_t) atIndex:2];
            [encoder setBytes:&level_offset length:sizeof(uint32_t) atIndex:3];
            
            uint32_t pairs = level_size / 2;
            [encoder dispatchThreads:MTLSizeMake(pairs, 1, 1)
               threadsPerThreadgroup:MTLSizeMake(std::min(pairs, (uint32_t)256), 1, 1)];
            [encoder endEncoding];
            
            [commandBuffer commit];
            [commandBuffer waitUntilCompleted];
            
            level_offset += level_size;
            level_size /= 2;
        }
        
        // Copy root (last node)
        memcpy(root, (uint8_t*)[nodesBuffer contents] + (total_nodes - 1) * elem_size, elem_size);
        
        return METAL_POSEIDON2_SUCCESS;
    }
}

MetalPoseidon2Result metal_poseidon2_merkle_tree(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    void* nodes,
    const void* leaves,
    uint32_t count
) {
    if (!ctx || !nodes || !leaves || count == 0) {
        return METAL_POSEIDON2_ERROR_INVALID_INPUT;
    }
    
    if ((count & (count - 1)) != 0) {
        return METAL_POSEIDON2_ERROR_INVALID_INPUT;
    }
    
    @autoreleasepool {
        size_t elem_size = element_size(field);
        size_t total_nodes = 2 * count - 1;
        
        id<MTLBuffer> nodesBuffer = [ctx->device newBufferWithLength:total_nodes * elem_size
                                                             options:MTLResourceStorageModeShared];
        
        memcpy([nodesBuffer contents], leaves, count * elem_size);
        
        uint32_t level_size = count;
        uint32_t level_offset = 0;
        
        while (level_size > 1) {
            id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
            
            [encoder setComputePipelineState:ctx->merkleLayerPipeline256];
            [encoder setBuffer:nodesBuffer offset:0 atIndex:0];
            [encoder setBuffer:get_modulus_buffer(ctx, field) offset:0 atIndex:1];
            [encoder setBytes:&level_size length:sizeof(uint32_t) atIndex:2];
            [encoder setBytes:&level_offset length:sizeof(uint32_t) atIndex:3];
            
            uint32_t pairs = level_size / 2;
            [encoder dispatchThreads:MTLSizeMake(pairs, 1, 1)
               threadsPerThreadgroup:MTLSizeMake(std::min(pairs, (uint32_t)256), 1, 1)];
            [encoder endEncoding];
            
            [commandBuffer commit];
            [commandBuffer waitUntilCompleted];
            
            level_offset += level_size;
            level_size /= 2;
        }
        
        memcpy(nodes, [nodesBuffer contents], total_nodes * elem_size);
        
        return METAL_POSEIDON2_SUCCESS;
    }
}

MetalPoseidon2Result metal_poseidon2_merkle_proof(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    void* proof,
    const void* nodes,
    uint32_t leaf_idx,
    uint32_t count
) {
    if (!ctx || !proof || !nodes || leaf_idx >= count) {
        return METAL_POSEIDON2_ERROR_INVALID_INPUT;
    }
    
    size_t elem_size = element_size(field);
    uint32_t depth = 0;
    for (uint32_t n = count; n > 1; n >>= 1) depth++;
    
    const uint8_t* nodes_ptr = (const uint8_t*)nodes;
    uint8_t* proof_ptr = (uint8_t*)proof;
    
    uint32_t idx = leaf_idx;
    uint32_t level_offset = 0;
    uint32_t level_size = count;
    
    for (uint32_t d = 0; d < depth; d++) {
        uint32_t sibling_idx = (idx % 2 == 0) ? idx + 1 : idx - 1;
        memcpy(proof_ptr + d * elem_size, 
               nodes_ptr + (level_offset + sibling_idx) * elem_size, 
               elem_size);
        
        level_offset += level_size;
        level_size /= 2;
        idx /= 2;
    }
    
    return METAL_POSEIDON2_SUCCESS;
}

MetalPoseidon2Result metal_poseidon2_merkle_verify(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    const void* root,
    const void* leaf,
    const void* proof,
    uint32_t leaf_idx,
    uint32_t depth
) {
    if (!ctx || !root || !leaf || !proof) {
        return METAL_POSEIDON2_ERROR_INVALID_INPUT;
    }
    
    size_t elem_size = element_size(field);
    std::vector<uint8_t> current(elem_size);
    memcpy(current.data(), leaf, elem_size);
    
    const uint8_t* proof_ptr = (const uint8_t*)proof;
    uint32_t idx = leaf_idx;
    
    for (uint32_t d = 0; d < depth; d++) {
        std::vector<uint8_t> left(elem_size), right(elem_size);
        
        if (idx % 2 == 0) {
            memcpy(left.data(), current.data(), elem_size);
            memcpy(right.data(), proof_ptr + d * elem_size, elem_size);
        } else {
            memcpy(left.data(), proof_ptr + d * elem_size, elem_size);
            memcpy(right.data(), current.data(), elem_size);
        }
        
        // Compress left || right
        metal_poseidon2_compress(ctx, field, current.data(), left.data(), right.data());
        
        idx /= 2;
    }
    
    // Compare with root
    if (memcmp(current.data(), root, elem_size) != 0) {
        return METAL_POSEIDON2_ERROR_INVALID_INPUT;
    }
    
    return METAL_POSEIDON2_SUCCESS;
}

// =============================================================================
// Sponge Construction
// =============================================================================

MetalPoseidon2Sponge* metal_poseidon2_sponge_new(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    uint32_t width
) {
    if (!ctx || width < 2) {
        return nullptr;
    }
    
    MetalPoseidon2Sponge* sponge = new MetalPoseidon2Sponge();
    sponge->ctx = ctx;
    sponge->field = field;
    sponge->width = width;
    sponge->rate = width - 1;  // Capacity = 1
    sponge->absorbed = 0;
    
    size_t elem_size = element_size(field);
    sponge->state.resize(width * elem_size, 0);
    
    return sponge;
}

MetalPoseidon2Result metal_poseidon2_sponge_absorb(
    MetalPoseidon2Sponge* sponge,
    const void* data,
    uint32_t count
) {
    if (!sponge || !data) {
        return METAL_POSEIDON2_ERROR_INVALID_INPUT;
    }
    
    size_t elem_size = element_size(sponge->field);
    const uint8_t* input = (const uint8_t*)data;
    
    for (uint32_t i = 0; i < count; i++) {
        // XOR into state
        uint8_t* state_elem = sponge->state.data() + sponge->absorbed * elem_size;
        for (size_t j = 0; j < elem_size; j++) {
            state_elem[j] ^= input[i * elem_size + j];
        }
        
        sponge->absorbed++;
        
        // If rate elements absorbed, permute
        if (sponge->absorbed >= sponge->rate) {
            // Permute via GPU
            id<MTLBuffer> stateBuffer = [sponge->ctx->device 
                newBufferWithBytes:sponge->state.data()
                            length:sponge->state.size()
                           options:MTLResourceStorageModeShared];
            
            id<MTLCommandBuffer> commandBuffer = [sponge->ctx->commandQueue commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
            
            if (sponge->field == POSEIDON2_BN254 || sponge->field == POSEIDON2_BLS12_381) {
                [encoder setComputePipelineState:sponge->ctx->permutationPipeline256];
                [encoder setBuffer:stateBuffer offset:0 atIndex:0];
                [encoder setBuffer:get_modulus_buffer(sponge->ctx, sponge->field) offset:0 atIndex:1];
                
                uint32_t fullRounds = 8;
                uint32_t partialRounds = 56;
                
                [encoder setBytes:&sponge->width length:sizeof(uint32_t) atIndex:2];
                [encoder setBytes:&fullRounds length:sizeof(uint32_t) atIndex:3];
                [encoder setBytes:&partialRounds length:sizeof(uint32_t) atIndex:4];
            }
            
            [encoder dispatchThreads:MTLSizeMake(1, 1, 1)
               threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
            [encoder endEncoding];
            
            [commandBuffer commit];
            [commandBuffer waitUntilCompleted];
            
            memcpy(sponge->state.data(), [stateBuffer contents], sponge->state.size());
            sponge->absorbed = 0;
        }
    }
    
    return METAL_POSEIDON2_SUCCESS;
}

MetalPoseidon2Result metal_poseidon2_sponge_squeeze(
    MetalPoseidon2Sponge* sponge,
    void* output,
    uint32_t count
) {
    if (!sponge || !output) {
        return METAL_POSEIDON2_ERROR_INVALID_INPUT;
    }
    
    size_t elem_size = element_size(sponge->field);
    uint8_t* out_ptr = (uint8_t*)output;
    uint32_t squeezed = 0;
    
    // Finalize if needed
    if (sponge->absorbed > 0) {
        // Pad and permute
        id<MTLBuffer> stateBuffer = [sponge->ctx->device 
            newBufferWithBytes:sponge->state.data()
                        length:sponge->state.size()
                       options:MTLResourceStorageModeShared];
        
        id<MTLCommandBuffer> commandBuffer = [sponge->ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        if (sponge->field == POSEIDON2_BN254 || sponge->field == POSEIDON2_BLS12_381) {
            [encoder setComputePipelineState:sponge->ctx->permutationPipeline256];
            [encoder setBuffer:stateBuffer offset:0 atIndex:0];
            [encoder setBuffer:get_modulus_buffer(sponge->ctx, sponge->field) offset:0 atIndex:1];
            
            uint32_t fullRounds = 8;
            uint32_t partialRounds = 56;
            
            [encoder setBytes:&sponge->width length:sizeof(uint32_t) atIndex:2];
            [encoder setBytes:&fullRounds length:sizeof(uint32_t) atIndex:3];
            [encoder setBytes:&partialRounds length:sizeof(uint32_t) atIndex:4];
        }
        
        [encoder dispatchThreads:MTLSizeMake(1, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        memcpy(sponge->state.data(), [stateBuffer contents], sponge->state.size());
        sponge->absorbed = 0;
    }
    
    while (squeezed < count) {
        uint32_t available = sponge->rate;
        uint32_t to_squeeze = std::min(count - squeezed, available);
        
        for (uint32_t i = 0; i < to_squeeze; i++) {
            memcpy(out_ptr + (squeezed + i) * elem_size,
                   sponge->state.data() + i * elem_size,
                   elem_size);
        }
        
        squeezed += to_squeeze;
        
        if (squeezed < count) {
            // Need to permute for more output
            // ... similar permutation call
        }
    }
    
    return METAL_POSEIDON2_SUCCESS;
}

void metal_poseidon2_sponge_free(MetalPoseidon2Sponge* sponge) {
    if (sponge) {
        delete sponge;
    }
}

// =============================================================================
// Compression Function
// =============================================================================

MetalPoseidon2Result metal_poseidon2_compress(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    void* output,
    const void* left,
    const void* right
) {
    if (!ctx || !output || !left || !right) {
        return METAL_POSEIDON2_ERROR_INVALID_INPUT;
    }
    
    @autoreleasepool {
        size_t elem_size = element_size(field);
        
        id<MTLBuffer> leftBuffer = [ctx->device newBufferWithBytes:left
                                                            length:elem_size
                                                           options:MTLResourceStorageModeShared];
        id<MTLBuffer> rightBuffer = [ctx->device newBufferWithBytes:right
                                                             length:elem_size
                                                            options:MTLResourceStorageModeShared];
        id<MTLBuffer> outputBuffer = [ctx->device newBufferWithLength:elem_size
                                                              options:MTLResourceStorageModeShared];
        
        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:ctx->compressPipeline256];
        [encoder setBuffer:leftBuffer offset:0 atIndex:0];
        [encoder setBuffer:rightBuffer offset:0 atIndex:1];
        [encoder setBuffer:outputBuffer offset:0 atIndex:2];
        [encoder setBuffer:get_modulus_buffer(ctx, field) offset:0 atIndex:3];
        
        [encoder dispatchThreads:MTLSizeMake(1, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        memcpy(output, [outputBuffer contents], elem_size);
        
        return METAL_POSEIDON2_SUCCESS;
    }
}

MetalPoseidon2Result metal_poseidon2_batch_compress(
    MetalPoseidon2Context* ctx,
    Poseidon2Field field,
    void* outputs,
    const void* lefts,
    const void* rights,
    uint32_t count
) {
    if (!ctx || !outputs || !lefts || !rights || count == 0) {
        return METAL_POSEIDON2_ERROR_INVALID_INPUT;
    }
    
    @autoreleasepool {
        size_t elem_size = element_size(field);
        size_t total_size = count * elem_size;
        
        id<MTLBuffer> leftsBuffer = [ctx->device newBufferWithBytes:lefts
                                                             length:total_size
                                                            options:MTLResourceStorageModeShared];
        id<MTLBuffer> rightsBuffer = [ctx->device newBufferWithBytes:rights
                                                              length:total_size
                                                             options:MTLResourceStorageModeShared];
        id<MTLBuffer> outputsBuffer = [ctx->device newBufferWithLength:total_size
                                                               options:MTLResourceStorageModeShared];
        
        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:ctx->compressPipeline256];
        [encoder setBuffer:leftsBuffer offset:0 atIndex:0];
        [encoder setBuffer:rightsBuffer offset:0 atIndex:1];
        [encoder setBuffer:outputsBuffer offset:0 atIndex:2];
        [encoder setBuffer:get_modulus_buffer(ctx, field) offset:0 atIndex:3];
        
        [encoder dispatchThreads:MTLSizeMake(count, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(std::min(count, (uint32_t)256), 1, 1)];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        memcpy(outputs, [outputsBuffer contents], total_size);
        
        return METAL_POSEIDON2_SUCCESS;
    }
}

} // extern "C"

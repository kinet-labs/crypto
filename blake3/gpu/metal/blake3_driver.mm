// =============================================================================
// Metal BLAKE3 - GPU Acceleration for BLAKE3 Hash
// =============================================================================
//
// High-performance BLAKE3 hashing with GPU parallelization.
// Based on the official BLAKE3 specification.
//

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include "kinet/crypto/metal_blake3.h"
#include <vector>
#include <cstring>
#include <algorithm>
#include <fstream>

// =============================================================================
// Metal Shader Source - BLAKE3
// =============================================================================

static const char* BLAKE3_SHADER_SOURCE = R"(
#include <metal_stdlib>
using namespace metal;

// BLAKE3 constants
constant uint32_t BLAKE3_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

// Domain separation flags
constant uint32_t CHUNK_START = 1;
constant uint32_t CHUNK_END = 2;
constant uint32_t PARENT = 4;
constant uint32_t ROOT = 8;
constant uint32_t KEYED_HASH = 16;
constant uint32_t DERIVE_KEY_CONTEXT = 32;
constant uint32_t DERIVE_KEY_MATERIAL = 64;

// Message permutation schedule
constant uint8_t MSG_SCHEDULE[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13}
};

// Quarter round function
void g(thread uint32_t* state, int a, int b, int c, int d, uint32_t mx, uint32_t my) {
    state[a] = state[a] + state[b] + mx;
    state[d] = ((state[d] ^ state[a]) >> 16) | ((state[d] ^ state[a]) << 16);
    state[c] = state[c] + state[d];
    state[b] = ((state[b] ^ state[c]) >> 12) | ((state[b] ^ state[c]) << 20);
    state[a] = state[a] + state[b] + my;
    state[d] = ((state[d] ^ state[a]) >> 8) | ((state[d] ^ state[a]) << 24);
    state[c] = state[c] + state[d];
    state[b] = ((state[b] ^ state[c]) >> 7) | ((state[b] ^ state[c]) << 25);
}

// BLAKE3 round function
void blake3_round(thread uint32_t* state, const thread uint32_t* msg, int round) {
    constant uint8_t* s = MSG_SCHEDULE[round];
    
    g(state, 0, 4, 8,  12, msg[s[0]],  msg[s[1]]);
    g(state, 1, 5, 9,  13, msg[s[2]],  msg[s[3]]);
    g(state, 2, 6, 10, 14, msg[s[4]],  msg[s[5]]);
    g(state, 3, 7, 11, 15, msg[s[6]],  msg[s[7]]);
    g(state, 0, 5, 10, 15, msg[s[8]],  msg[s[9]]);
    g(state, 1, 6, 11, 12, msg[s[10]], msg[s[11]]);
    g(state, 2, 7, 8,  13, msg[s[12]], msg[s[13]]);
    g(state, 3, 4, 9,  14, msg[s[14]], msg[s[15]]);
}

// BLAKE3 compression function
void blake3_compress(
    thread uint32_t* cv_out,
    const thread uint32_t* cv_in,
    const thread uint32_t* block,
    uint64_t counter,
    uint32_t block_len,
    uint32_t flags
) {
    uint32_t state[16];
    
    // Initialize state
    for (int i = 0; i < 8; i++) state[i] = cv_in[i];
    for (int i = 0; i < 4; i++) state[8 + i] = BLAKE3_IV[i];
    state[12] = (uint32_t)counter;
    state[13] = (uint32_t)(counter >> 32);
    state[14] = block_len;
    state[15] = flags;
    
    // 7 rounds
    for (int r = 0; r < 7; r++) {
        blake3_round(state, block, r);
    }
    
    // XOR output
    for (int i = 0; i < 8; i++) {
        cv_out[i] = state[i] ^ state[i + 8];
    }
}

// Hash a single chunk (up to 1024 bytes)
void blake3_hash_chunk(
    thread uint32_t* cv_out,
    const device uint8_t* chunk,
    uint32_t chunk_len,
    const thread uint32_t* key,
    uint64_t chunk_counter,
    uint32_t flags
) {
    uint32_t cv[8];
    for (int i = 0; i < 8; i++) cv[i] = key[i];
    
    uint32_t blocks = (chunk_len + 63) / 64;
    if (blocks == 0) blocks = 1;
    
    for (uint32_t b = 0; b < blocks; b++) {
        uint32_t block[16] = {0};
        
        // Load block (little-endian)
        uint32_t offset = b * 64;
        uint32_t remaining = (chunk_len > offset) ? chunk_len - offset : 0;
        uint32_t to_copy = min(remaining, 64u);
        
        for (uint32_t i = 0; i < to_copy; i++) {
            block[i / 4] |= ((uint32_t)chunk[offset + i]) << ((i % 4) * 8);
        }
        
        uint32_t block_flags = flags;
        if (b == 0) block_flags |= CHUNK_START;
        if (b == blocks - 1) block_flags |= CHUNK_END;
        
        uint32_t block_len = min(to_copy, 64u);
        blake3_compress(cv, cv, block, chunk_counter, block_len, block_flags);
    }
    
    for (int i = 0; i < 8; i++) cv_out[i] = cv[i];
}

// Kernel: Hash fixed-size inputs in parallel
kernel void blake3_batch_hash_fixed(
    device const uint8_t* inputs [[buffer(0)]],
    device uint8_t* outputs [[buffer(1)]],
    constant uint32_t& input_len [[buffer(2)]],
    constant uint32_t* key [[buffer(3)]],
    constant uint32_t& flags [[buffer(4)]],
    uint32_t tid [[thread_position_in_grid]]
) {
    uint32_t cv[8];
    
    const device uint8_t* my_input = inputs + tid * input_len;
    device uint8_t* my_output = outputs + tid * 32;
    
    // Hash the input as a single chunk
    blake3_hash_chunk(cv, my_input, input_len, key, (uint64_t)tid, flags | ROOT);
    
    // Output (little-endian)
    for (int i = 0; i < 8; i++) {
        my_output[i * 4 + 0] = cv[i] & 0xFF;
        my_output[i * 4 + 1] = (cv[i] >> 8) & 0xFF;
        my_output[i * 4 + 2] = (cv[i] >> 16) & 0xFF;
        my_output[i * 4 + 3] = (cv[i] >> 24) & 0xFF;
    }
}

// Kernel: Process chunks in parallel (for large files)
kernel void blake3_process_chunks(
    device const uint8_t* data [[buffer(0)]],
    device uint32_t* chunk_cvs [[buffer(1)]],
    constant uint32_t* key [[buffer(2)]],
    constant uint32_t& num_chunks [[buffer(3)]],
    constant uint32_t& last_chunk_len [[buffer(4)]],
    constant uint32_t& flags [[buffer(5)]],
    uint32_t tid [[thread_position_in_grid]]
) {
    if (tid >= num_chunks) return;
    
    uint32_t chunk_len = 1024;
    if (tid == num_chunks - 1) {
        chunk_len = last_chunk_len;
    }
    
    const device uint8_t* chunk = data + (uint64_t)tid * 1024;
    device uint32_t* cv_out = chunk_cvs + tid * 8;
    
    uint32_t cv[8];
    blake3_hash_chunk(cv, chunk, chunk_len, key, (uint64_t)tid, flags);
    
    for (int i = 0; i < 8; i++) {
        cv_out[i] = cv[i];
    }
}

// Kernel: Parent node hash (merge two children)
kernel void blake3_parent_hash(
    device const uint32_t* children [[buffer(0)]],
    device uint32_t* parents [[buffer(1)]],
    constant uint32_t* key [[buffer(2)]],
    constant uint32_t& flags [[buffer(3)]],
    uint32_t tid [[thread_position_in_grid]]
) {
    const device uint32_t* left = children + tid * 16;
    const device uint32_t* right = children + tid * 16 + 8;
    device uint32_t* parent = parents + tid * 8;
    
    uint32_t block[16];
    for (int i = 0; i < 8; i++) block[i] = left[i];
    for (int i = 0; i < 8; i++) block[8 + i] = right[i];
    
    uint32_t cv[8];
    for (int i = 0; i < 8; i++) cv[i] = key[i];
    
    blake3_compress(cv, cv, block, 0, 64, flags | PARENT);
    
    for (int i = 0; i < 8; i++) {
        parent[i] = cv[i];
    }
}

// Kernel: Merkle tree layer
kernel void blake3_merkle_layer(
    device const uint8_t* children [[buffer(0)]],
    device uint8_t* parents [[buffer(1)]],
    constant uint32_t* key [[buffer(2)]],
    uint32_t tid [[thread_position_in_grid]]
) {
    const device uint8_t* left = children + tid * 64;
    const device uint8_t* right = children + tid * 64 + 32;
    device uint8_t* parent_out = parents + tid * 32;
    
    uint32_t block[16];
    
    // Load children as little-endian words
    for (int i = 0; i < 8; i++) {
        block[i] = ((uint32_t)left[i*4]) | 
                   ((uint32_t)left[i*4+1] << 8) |
                   ((uint32_t)left[i*4+2] << 16) |
                   ((uint32_t)left[i*4+3] << 24);
    }
    for (int i = 0; i < 8; i++) {
        block[8+i] = ((uint32_t)right[i*4]) | 
                     ((uint32_t)right[i*4+1] << 8) |
                     ((uint32_t)right[i*4+2] << 16) |
                     ((uint32_t)right[i*4+3] << 24);
    }
    
    uint32_t cv[8];
    for (int i = 0; i < 8; i++) cv[i] = key[i];
    
    blake3_compress(cv, cv, block, 0, 64, PARENT);
    
    for (int i = 0; i < 8; i++) {
        parent_out[i*4]   = cv[i] & 0xFF;
        parent_out[i*4+1] = (cv[i] >> 8) & 0xFF;
        parent_out[i*4+2] = (cv[i] >> 16) & 0xFF;
        parent_out[i*4+3] = (cv[i] >> 24) & 0xFF;
    }
}
)";

// =============================================================================
// Context Structure
// =============================================================================

struct MetalBLAKE3Context {
    id<MTLDevice> device;
    id<MTLCommandQueue> commandQueue;
    id<MTLComputePipelineState> batchHashFixedPipeline;
    id<MTLComputePipelineState> processChunksPipeline;
    id<MTLComputePipelineState> parentHashPipeline;
    id<MTLComputePipelineState> merkleLayerPipeline;
    id<MTLBuffer> ivBuffer;
};

struct MetalBLAKE3Hasher {
    MetalBLAKE3Context* ctx;
    uint32_t key[8];
    uint32_t flags;
    std::vector<uint8_t> buffer;
    std::vector<std::array<uint32_t, 8>> chunk_cvs;
    uint64_t chunk_counter;
    uint32_t buf_len;
};

// =============================================================================
// Context Management
// =============================================================================

extern "C" {

MetalBLAKE3Context* metal_blake3_init(void) {
    @autoreleasepool {
        MetalBLAKE3Context* ctx = new MetalBLAKE3Context();
        
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
        NSString* source = [NSString stringWithUTF8String:BLAKE3_SHADER_SOURCE];
        id<MTLLibrary> library = [ctx->device newLibraryWithSource:source options:nil error:&error];
        
        if (!library) {
            NSLog(@"BLAKE3 shader compilation failed: %@", error);
            delete ctx;
            return nullptr;
        }
        
        // Create pipelines
        id<MTLFunction> batchHashFixedFunc = [library newFunctionWithName:@"blake3_batch_hash_fixed"];
        if (batchHashFixedFunc) {
            ctx->batchHashFixedPipeline = [ctx->device newComputePipelineStateWithFunction:batchHashFixedFunc error:&error];
        }
        
        id<MTLFunction> processChunksFunc = [library newFunctionWithName:@"blake3_process_chunks"];
        if (processChunksFunc) {
            ctx->processChunksPipeline = [ctx->device newComputePipelineStateWithFunction:processChunksFunc error:&error];
        }
        
        id<MTLFunction> parentHashFunc = [library newFunctionWithName:@"blake3_parent_hash"];
        if (parentHashFunc) {
            ctx->parentHashPipeline = [ctx->device newComputePipelineStateWithFunction:parentHashFunc error:&error];
        }
        
        id<MTLFunction> merkleLayerFunc = [library newFunctionWithName:@"blake3_merkle_layer"];
        if (merkleLayerFunc) {
            ctx->merkleLayerPipeline = [ctx->device newComputePipelineStateWithFunction:merkleLayerFunc error:&error];
        }
        
        // BLAKE3 IV
        uint32_t iv[8] = {
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
        };
        ctx->ivBuffer = [ctx->device newBufferWithBytes:iv length:32 options:MTLResourceStorageModeShared];
        
        return ctx;
    }
}

void metal_blake3_destroy(MetalBLAKE3Context* ctx) {
    if (ctx) {
        delete ctx;
    }
}

bool metal_blake3_available(void) {
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    return device != nil;
}

// =============================================================================
// Helper: Software BLAKE3 compression for small inputs
// =============================================================================

static const uint32_t BLAKE3_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static const uint8_t MSG_SCHEDULE[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13}
};

static inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void g_cpu(uint32_t* state, int a, int b, int c, int d, uint32_t mx, uint32_t my) {
    state[a] = state[a] + state[b] + mx;
    state[d] = rotr32(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = rotr32(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 7);
}

static void blake3_round_cpu(uint32_t* state, const uint32_t* msg, int round) {
    const uint8_t* s = MSG_SCHEDULE[round];
    g_cpu(state, 0, 4, 8,  12, msg[s[0]],  msg[s[1]]);
    g_cpu(state, 1, 5, 9,  13, msg[s[2]],  msg[s[3]]);
    g_cpu(state, 2, 6, 10, 14, msg[s[4]],  msg[s[5]]);
    g_cpu(state, 3, 7, 11, 15, msg[s[6]],  msg[s[7]]);
    g_cpu(state, 0, 5, 10, 15, msg[s[8]],  msg[s[9]]);
    g_cpu(state, 1, 6, 11, 12, msg[s[10]], msg[s[11]]);
    g_cpu(state, 2, 7, 8,  13, msg[s[12]], msg[s[13]]);
    g_cpu(state, 3, 4, 9,  14, msg[s[14]], msg[s[15]]);
}

static void blake3_compress_cpu(
    uint32_t* cv_out,
    const uint32_t* cv_in,
    const uint32_t* block,
    uint64_t counter,
    uint32_t block_len,
    uint32_t flags
) {
    uint32_t state[16];
    
    for (int i = 0; i < 8; i++) state[i] = cv_in[i];
    for (int i = 0; i < 4; i++) state[8 + i] = BLAKE3_IV[i];
    state[12] = (uint32_t)counter;
    state[13] = (uint32_t)(counter >> 32);
    state[14] = block_len;
    state[15] = flags;
    
    for (int r = 0; r < 7; r++) {
        blake3_round_cpu(state, block, r);
    }
    
    for (int i = 0; i < 8; i++) {
        cv_out[i] = state[i] ^ state[i + 8];
    }
}

static void blake3_hash_chunk_cpu(
    uint32_t* cv_out,
    const uint8_t* chunk,
    uint32_t chunk_len,
    const uint32_t* key,
    uint64_t chunk_counter,
    uint32_t flags
) {
    uint32_t cv[8];
    for (int i = 0; i < 8; i++) cv[i] = key[i];
    
    uint32_t blocks = (chunk_len + 63) / 64;
    if (blocks == 0) blocks = 1;
    
    for (uint32_t b = 0; b < blocks; b++) {
        uint32_t block[16] = {0};
        
        uint32_t offset = b * 64;
        uint32_t remaining = (chunk_len > offset) ? chunk_len - offset : 0;
        uint32_t to_copy = std::min(remaining, 64u);
        
        for (uint32_t i = 0; i < to_copy; i++) {
            block[i / 4] |= ((uint32_t)chunk[offset + i]) << ((i % 4) * 8);
        }
        
        uint32_t block_flags = flags;
        if (b == 0) block_flags |= 1;  // CHUNK_START
        if (b == blocks - 1) block_flags |= 2;  // CHUNK_END
        
        blake3_compress_cpu(cv, cv, block, chunk_counter, std::min(to_copy, 64u), block_flags);
    }
    
    for (int i = 0; i < 8; i++) cv_out[i] = cv[i];
}

// =============================================================================
// Simple Hash Interface
// =============================================================================

MetalBLAKE3Result metal_blake3_hash(
    MetalBLAKE3Context* ctx,
    uint8_t* output,
    size_t out_len,
    const uint8_t* input,
    size_t in_len
) {
    if (!ctx || !output || out_len < 32) {
        return METAL_BLAKE3_ERROR_INVALID_INPUT;
    }
    
    // For small inputs, use CPU
    if (in_len <= 1024) {
        uint32_t cv[8];
        blake3_hash_chunk_cpu(cv, input, (uint32_t)in_len, BLAKE3_IV, 0, 8);  // ROOT flag
        
        for (int i = 0; i < 8; i++) {
            output[i * 4 + 0] = cv[i] & 0xFF;
            output[i * 4 + 1] = (cv[i] >> 8) & 0xFF;
            output[i * 4 + 2] = (cv[i] >> 16) & 0xFF;
            output[i * 4 + 3] = (cv[i] >> 24) & 0xFF;
        }
        
        return METAL_BLAKE3_SUCCESS;
    }
    
    // For larger inputs, use GPU
    @autoreleasepool {
        uint32_t num_chunks = (uint32_t)((in_len + 1023) / 1024);
        uint32_t last_chunk_len = (uint32_t)(in_len % 1024);
        if (last_chunk_len == 0) last_chunk_len = 1024;
        
        id<MTLBuffer> inputBuffer = [ctx->device newBufferWithBytes:input
                                                             length:in_len
                                                            options:MTLResourceStorageModeShared];
        id<MTLBuffer> chunkCVsBuffer = [ctx->device newBufferWithLength:num_chunks * 32
                                                                options:MTLResourceStorageModeShared];
        
        uint32_t flags = 0;
        
        // Process chunks
        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:ctx->processChunksPipeline];
        [encoder setBuffer:inputBuffer offset:0 atIndex:0];
        [encoder setBuffer:chunkCVsBuffer offset:0 atIndex:1];
        [encoder setBuffer:ctx->ivBuffer offset:0 atIndex:2];
        [encoder setBytes:&num_chunks length:sizeof(uint32_t) atIndex:3];
        [encoder setBytes:&last_chunk_len length:sizeof(uint32_t) atIndex:4];
        [encoder setBytes:&flags length:sizeof(uint32_t) atIndex:5];
        
        [encoder dispatchThreads:MTLSizeMake(num_chunks, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(std::min(num_chunks, (uint32_t)256), 1, 1)];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        // Merge chunks into tree
        std::vector<uint32_t> cvs(num_chunks * 8);
        memcpy(cvs.data(), [chunkCVsBuffer contents], num_chunks * 32);
        
        while (num_chunks > 1) {
            uint32_t pairs = num_chunks / 2;
            std::vector<uint32_t> parents(pairs * 8);
            
            for (uint32_t i = 0; i < pairs; i++) {
                uint32_t block[16];
                for (int j = 0; j < 8; j++) block[j] = cvs[i * 16 + j];
                for (int j = 0; j < 8; j++) block[8 + j] = cvs[i * 16 + 8 + j];
                
                uint32_t parent_flags = 4;  // PARENT
                if (pairs == 1 && (num_chunks % 2 == 0)) {
                    parent_flags |= 8;  // ROOT
                }
                
                uint32_t cv[8];
                for (int j = 0; j < 8; j++) cv[j] = BLAKE3_IV[j];
                blake3_compress_cpu(cv, cv, block, 0, 64, parent_flags);
                
                for (int j = 0; j < 8; j++) parents[i * 8 + j] = cv[j];
            }
            
            // Handle odd chunk
            if (num_chunks % 2 == 1) {
                for (int j = 0; j < 8; j++) {
                    parents.push_back(cvs[(num_chunks - 1) * 8 + j]);
                }
                num_chunks = pairs + 1;
            } else {
                num_chunks = pairs;
            }
            
            cvs = std::move(parents);
        }
        
        // Output root
        for (int i = 0; i < 8; i++) {
            output[i * 4 + 0] = cvs[i] & 0xFF;
            output[i * 4 + 1] = (cvs[i] >> 8) & 0xFF;
            output[i * 4 + 2] = (cvs[i] >> 16) & 0xFF;
            output[i * 4 + 3] = (cvs[i] >> 24) & 0xFF;
        }
        
        return METAL_BLAKE3_SUCCESS;
    }
}

MetalBLAKE3Result metal_blake3_batch_hash(
    MetalBLAKE3Context* ctx,
    uint8_t* outputs,
    const uint8_t** inputs,
    const size_t* in_lens,
    uint32_t count
) {
    if (!ctx || !outputs || !inputs || !in_lens || count == 0) {
        return METAL_BLAKE3_ERROR_INVALID_INPUT;
    }
    
    // Process each input (could optimize by grouping by size)
    for (uint32_t i = 0; i < count; i++) {
        MetalBLAKE3Result result = metal_blake3_hash(ctx, outputs + i * 32, 32, inputs[i], in_lens[i]);
        if (result != METAL_BLAKE3_SUCCESS) {
            return result;
        }
    }
    
    return METAL_BLAKE3_SUCCESS;
}

MetalBLAKE3Result metal_blake3_batch_hash_fixed(
    MetalBLAKE3Context* ctx,
    uint8_t* outputs,
    const uint8_t* inputs,
    size_t in_len,
    uint32_t count
) {
    if (!ctx || !outputs || !inputs || count == 0) {
        return METAL_BLAKE3_ERROR_INVALID_INPUT;
    }
    
    @autoreleasepool {
        id<MTLBuffer> inputBuffer = [ctx->device newBufferWithBytes:inputs
                                                             length:in_len * count
                                                            options:MTLResourceStorageModeShared];
        id<MTLBuffer> outputBuffer = [ctx->device newBufferWithLength:count * 32
                                                              options:MTLResourceStorageModeShared];
        
        uint32_t input_len_u32 = (uint32_t)in_len;
        uint32_t flags = 0;
        
        id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:ctx->batchHashFixedPipeline];
        [encoder setBuffer:inputBuffer offset:0 atIndex:0];
        [encoder setBuffer:outputBuffer offset:0 atIndex:1];
        [encoder setBytes:&input_len_u32 length:sizeof(uint32_t) atIndex:2];
        [encoder setBuffer:ctx->ivBuffer offset:0 atIndex:3];
        [encoder setBytes:&flags length:sizeof(uint32_t) atIndex:4];
        
        [encoder dispatchThreads:MTLSizeMake(count, 1, 1)
           threadsPerThreadgroup:MTLSizeMake(std::min(count, (uint32_t)256), 1, 1)];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        memcpy(outputs, [outputBuffer contents], count * 32);
        
        return METAL_BLAKE3_SUCCESS;
    }
}

// =============================================================================
// Keyed Hash
// =============================================================================

MetalBLAKE3Result metal_blake3_keyed_hash(
    MetalBLAKE3Context* ctx,
    uint8_t* output,
    size_t out_len,
    const uint8_t key[BLAKE3_KEY_LEN],
    const uint8_t* input,
    size_t in_len
) {
    if (!ctx || !output || !key || out_len < 32) {
        return METAL_BLAKE3_ERROR_INVALID_INPUT;
    }
    
    // Convert key bytes to words
    uint32_t key_words[8];
    for (int i = 0; i < 8; i++) {
        key_words[i] = ((uint32_t)key[i*4]) |
                       ((uint32_t)key[i*4+1] << 8) |
                       ((uint32_t)key[i*4+2] << 16) |
                       ((uint32_t)key[i*4+3] << 24);
    }
    
    uint32_t cv[8];
    blake3_hash_chunk_cpu(cv, input, (uint32_t)in_len, key_words, 0, 16 | 8);  // KEYED_HASH | ROOT
    
    for (int i = 0; i < 8; i++) {
        output[i * 4 + 0] = cv[i] & 0xFF;
        output[i * 4 + 1] = (cv[i] >> 8) & 0xFF;
        output[i * 4 + 2] = (cv[i] >> 16) & 0xFF;
        output[i * 4 + 3] = (cv[i] >> 24) & 0xFF;
    }
    
    return METAL_BLAKE3_SUCCESS;
}

MetalBLAKE3Result metal_blake3_batch_keyed_hash(
    MetalBLAKE3Context* ctx,
    uint8_t* outputs,
    const uint8_t key[BLAKE3_KEY_LEN],
    const uint8_t** inputs,
    const size_t* in_lens,
    uint32_t count
) {
    for (uint32_t i = 0; i < count; i++) {
        MetalBLAKE3Result result = metal_blake3_keyed_hash(ctx, outputs + i * 32, 32, key, inputs[i], in_lens[i]);
        if (result != METAL_BLAKE3_SUCCESS) {
            return result;
        }
    }
    return METAL_BLAKE3_SUCCESS;
}

// =============================================================================
// Key Derivation
// =============================================================================

MetalBLAKE3Result metal_blake3_derive_key(
    MetalBLAKE3Context* ctx,
    uint8_t* output,
    size_t out_len,
    const char* context,
    size_t context_len,
    const uint8_t* key_material,
    size_t km_len
) {
    if (!ctx || !output || !context || !key_material || out_len < 32) {
        return METAL_BLAKE3_ERROR_INVALID_INPUT;
    }
    
    // First: hash context string with DERIVE_KEY_CONTEXT flag
    uint32_t context_key[8];
    blake3_hash_chunk_cpu(context_key, (const uint8_t*)context, (uint32_t)context_len, BLAKE3_IV, 0, 32 | 8);  // DERIVE_KEY_CONTEXT | ROOT
    
    // Second: hash key material with derived context key and DERIVE_KEY_MATERIAL flag
    uint32_t cv[8];
    blake3_hash_chunk_cpu(cv, key_material, (uint32_t)km_len, context_key, 0, 64 | 8);  // DERIVE_KEY_MATERIAL | ROOT
    
    for (int i = 0; i < 8; i++) {
        output[i * 4 + 0] = cv[i] & 0xFF;
        output[i * 4 + 1] = (cv[i] >> 8) & 0xFF;
        output[i * 4 + 2] = (cv[i] >> 16) & 0xFF;
        output[i * 4 + 3] = (cv[i] >> 24) & 0xFF;
    }
    
    return METAL_BLAKE3_SUCCESS;
}

// =============================================================================
// Streaming Interface
// =============================================================================

MetalBLAKE3Hasher* metal_blake3_hasher_new(MetalBLAKE3Context* ctx) {
    if (!ctx) return nullptr;
    
    MetalBLAKE3Hasher* hasher = new MetalBLAKE3Hasher();
    hasher->ctx = ctx;
    for (int i = 0; i < 8; i++) hasher->key[i] = BLAKE3_IV[i];
    hasher->flags = 0;
    hasher->buffer.reserve(1024);
    hasher->chunk_counter = 0;
    hasher->buf_len = 0;
    
    return hasher;
}

MetalBLAKE3Hasher* metal_blake3_hasher_new_keyed(
    MetalBLAKE3Context* ctx,
    const uint8_t key[BLAKE3_KEY_LEN]
) {
    if (!ctx || !key) return nullptr;
    
    MetalBLAKE3Hasher* hasher = new MetalBLAKE3Hasher();
    hasher->ctx = ctx;
    
    for (int i = 0; i < 8; i++) {
        hasher->key[i] = ((uint32_t)key[i*4]) |
                         ((uint32_t)key[i*4+1] << 8) |
                         ((uint32_t)key[i*4+2] << 16) |
                         ((uint32_t)key[i*4+3] << 24);
    }
    
    hasher->flags = 16;  // KEYED_HASH
    hasher->buffer.reserve(1024);
    hasher->chunk_counter = 0;
    hasher->buf_len = 0;
    
    return hasher;
}

MetalBLAKE3Hasher* metal_blake3_hasher_new_derive_key(
    MetalBLAKE3Context* ctx,
    const char* context,
    size_t context_len
) {
    if (!ctx || !context) return nullptr;
    
    MetalBLAKE3Hasher* hasher = new MetalBLAKE3Hasher();
    hasher->ctx = ctx;
    
    // Derive key from context
    blake3_hash_chunk_cpu(hasher->key, (const uint8_t*)context, (uint32_t)context_len, BLAKE3_IV, 0, 32 | 8);
    
    hasher->flags = 64;  // DERIVE_KEY_MATERIAL
    hasher->buffer.reserve(1024);
    hasher->chunk_counter = 0;
    hasher->buf_len = 0;
    
    return hasher;
}

MetalBLAKE3Result metal_blake3_hasher_update(
    MetalBLAKE3Hasher* hasher,
    const uint8_t* input,
    size_t in_len
) {
    if (!hasher || (!input && in_len > 0)) {
        return METAL_BLAKE3_ERROR_INVALID_INPUT;
    }
    
    size_t consumed = 0;
    while (consumed < in_len) {
        size_t space = 1024 - hasher->buf_len;
        size_t to_copy = std::min(space, in_len - consumed);
        
        hasher->buffer.resize(hasher->buf_len + to_copy);
        memcpy(hasher->buffer.data() + hasher->buf_len, input + consumed, to_copy);
        hasher->buf_len += to_copy;
        consumed += to_copy;
        
        if (hasher->buf_len == 1024) {
            // Complete chunk - hash it
            std::array<uint32_t, 8> cv;
            blake3_hash_chunk_cpu(cv.data(), hasher->buffer.data(), 1024, hasher->key, hasher->chunk_counter, hasher->flags);
            hasher->chunk_cvs.push_back(cv);
            hasher->chunk_counter++;
            hasher->buf_len = 0;
            hasher->buffer.clear();
        }
    }
    
    return METAL_BLAKE3_SUCCESS;
}

MetalBLAKE3Result metal_blake3_hasher_finalize(
    MetalBLAKE3Hasher* hasher,
    uint8_t* output,
    size_t out_len
) {
    if (!hasher || !output || out_len < 32) {
        return METAL_BLAKE3_ERROR_INVALID_INPUT;
    }
    
    // Finalize last chunk
    std::array<uint32_t, 8> last_cv;
    if (hasher->buf_len > 0 || hasher->chunk_cvs.empty()) {
        uint32_t flags = hasher->flags;
        if (hasher->chunk_cvs.empty()) flags |= 8;  // ROOT if only chunk
        blake3_hash_chunk_cpu(last_cv.data(), hasher->buffer.data(), hasher->buf_len, hasher->key, hasher->chunk_counter, flags);
        hasher->chunk_cvs.push_back(last_cv);
    }
    
    // Merge tree
    std::vector<std::array<uint32_t, 8>> cvs = hasher->chunk_cvs;
    
    while (cvs.size() > 1) {
        std::vector<std::array<uint32_t, 8>> parents;
        
        for (size_t i = 0; i + 1 < cvs.size(); i += 2) {
            uint32_t block[16];
            for (int j = 0; j < 8; j++) block[j] = cvs[i][j];
            for (int j = 0; j < 8; j++) block[8 + j] = cvs[i + 1][j];
            
            uint32_t parent_flags = 4;  // PARENT
            if (parents.empty() && i + 2 >= cvs.size()) {
                parent_flags |= 8;  // ROOT
            }
            
            std::array<uint32_t, 8> parent;
            for (int j = 0; j < 8; j++) parent[j] = hasher->key[j];
            blake3_compress_cpu(parent.data(), parent.data(), block, 0, 64, parent_flags);
            parents.push_back(parent);
        }
        
        if (cvs.size() % 2 == 1) {
            parents.push_back(cvs.back());
        }
        
        cvs = std::move(parents);
    }
    
    // Output
    for (int i = 0; i < 8; i++) {
        output[i * 4 + 0] = cvs[0][i] & 0xFF;
        output[i * 4 + 1] = (cvs[0][i] >> 8) & 0xFF;
        output[i * 4 + 2] = (cvs[0][i] >> 16) & 0xFF;
        output[i * 4 + 3] = (cvs[0][i] >> 24) & 0xFF;
    }
    
    return METAL_BLAKE3_SUCCESS;
}

void metal_blake3_hasher_reset(MetalBLAKE3Hasher* hasher) {
    if (hasher) {
        hasher->buffer.clear();
        hasher->chunk_cvs.clear();
        hasher->chunk_counter = 0;
        hasher->buf_len = 0;
    }
}

void metal_blake3_hasher_free(MetalBLAKE3Hasher* hasher) {
    if (hasher) {
        delete hasher;
    }
}

// =============================================================================
// Merkle Tree
// =============================================================================

MetalBLAKE3Result metal_blake3_merkle_root(
    MetalBLAKE3Context* ctx,
    uint8_t root[BLAKE3_OUT_LEN],
    const uint8_t* leaves,
    uint32_t count
) {
    if (!ctx || !root || !leaves || count == 0) {
        return METAL_BLAKE3_ERROR_INVALID_INPUT;
    }
    
    if ((count & (count - 1)) != 0) {
        return METAL_BLAKE3_ERROR_INVALID_INPUT;  // Must be power of 2
    }
    
    @autoreleasepool {
        id<MTLBuffer> nodesBuffer = [ctx->device newBufferWithBytes:leaves
                                                             length:count * 32
                                                            options:MTLResourceStorageModeShared];
        
        uint32_t level_size = count;
        
        while (level_size > 1) {
            id<MTLBuffer> parentsBuffer = [ctx->device newBufferWithLength:(level_size / 2) * 32
                                                                   options:MTLResourceStorageModeShared];
            
            id<MTLCommandBuffer> commandBuffer = [ctx->commandQueue commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
            
            [encoder setComputePipelineState:ctx->merkleLayerPipeline];
            [encoder setBuffer:nodesBuffer offset:0 atIndex:0];
            [encoder setBuffer:parentsBuffer offset:0 atIndex:1];
            [encoder setBuffer:ctx->ivBuffer offset:0 atIndex:2];
            
            uint32_t pairs = level_size / 2;
            [encoder dispatchThreads:MTLSizeMake(pairs, 1, 1)
               threadsPerThreadgroup:MTLSizeMake(std::min(pairs, (uint32_t)256), 1, 1)];
            [encoder endEncoding];
            
            [commandBuffer commit];
            [commandBuffer waitUntilCompleted];
            
            nodesBuffer = parentsBuffer;
            level_size /= 2;
        }
        
        memcpy(root, [nodesBuffer contents], 32);
        
        return METAL_BLAKE3_SUCCESS;
    }
}

MetalBLAKE3Result metal_blake3_merkle_tree(
    MetalBLAKE3Context* ctx,
    uint8_t* nodes,
    const uint8_t* leaves,
    uint32_t count
) {
    if (!ctx || !nodes || !leaves || count == 0) {
        return METAL_BLAKE3_ERROR_INVALID_INPUT;
    }
    
    if ((count & (count - 1)) != 0) {
        return METAL_BLAKE3_ERROR_INVALID_INPUT;
    }
    
    // Copy leaves to output
    memcpy(nodes, leaves, count * 32);
    
    uint32_t offset = 0;
    uint32_t level_size = count;
    
    while (level_size > 1) {
        uint32_t pairs = level_size / 2;
        uint8_t* children = nodes + offset * 32;
        uint8_t* parents = nodes + (offset + level_size) * 32;
        
        for (uint32_t i = 0; i < pairs; i++) {
            uint32_t block[16];
            
            const uint8_t* left = children + i * 64;
            const uint8_t* right = children + i * 64 + 32;
            
            for (int j = 0; j < 8; j++) {
                block[j] = ((uint32_t)left[j*4]) |
                           ((uint32_t)left[j*4+1] << 8) |
                           ((uint32_t)left[j*4+2] << 16) |
                           ((uint32_t)left[j*4+3] << 24);
            }
            for (int j = 0; j < 8; j++) {
                block[8+j] = ((uint32_t)right[j*4]) |
                             ((uint32_t)right[j*4+1] << 8) |
                             ((uint32_t)right[j*4+2] << 16) |
                             ((uint32_t)right[j*4+3] << 24);
            }
            
            uint32_t cv[8];
            for (int j = 0; j < 8; j++) cv[j] = BLAKE3_IV[j];
            blake3_compress_cpu(cv, cv, block, 0, 64, 4);  // PARENT
            
            uint8_t* parent = parents + i * 32;
            for (int j = 0; j < 8; j++) {
                parent[j*4]   = cv[j] & 0xFF;
                parent[j*4+1] = (cv[j] >> 8) & 0xFF;
                parent[j*4+2] = (cv[j] >> 16) & 0xFF;
                parent[j*4+3] = (cv[j] >> 24) & 0xFF;
            }
        }
        
        offset += level_size;
        level_size /= 2;
    }
    
    return METAL_BLAKE3_SUCCESS;
}

// =============================================================================
// File Hashing
// =============================================================================

MetalBLAKE3Result metal_blake3_hash_file(
    MetalBLAKE3Context* ctx,
    uint8_t* output,
    size_t out_len,
    const char* path
) {
    if (!ctx || !output || !path || out_len < 32) {
        return METAL_BLAKE3_ERROR_INVALID_INPUT;
    }
    
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return METAL_BLAKE3_ERROR_INVALID_INPUT;
    }
    
    size_t file_size = file.tellg();
    file.seekg(0);
    
    if (file_size <= 1024 * 1024) {
        // Small file - read all at once
        std::vector<uint8_t> data(file_size);
        file.read((char*)data.data(), file_size);
        return metal_blake3_hash(ctx, output, out_len, data.data(), file_size);
    }
    
    // Large file - stream with hasher
    MetalBLAKE3Hasher* hasher = metal_blake3_hasher_new(ctx);
    if (!hasher) {
        return METAL_BLAKE3_ERROR_INIT;
    }
    
    std::vector<uint8_t> buffer(1024 * 1024);  // 1MB chunks
    
    while (file) {
        file.read((char*)buffer.data(), buffer.size());
        size_t bytes_read = file.gcount();
        if (bytes_read > 0) {
            metal_blake3_hasher_update(hasher, buffer.data(), bytes_read);
        }
    }
    
    MetalBLAKE3Result result = metal_blake3_hasher_finalize(hasher, output, out_len);
    metal_blake3_hasher_free(hasher);
    
    return result;
}

} // extern "C"

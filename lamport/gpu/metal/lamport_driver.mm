// =============================================================================
// Metal Lamport Implementation - GPU Hash-Based Signatures
// =============================================================================

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#include "kinet/crypto/metal_lamport.h"
#include <mutex>
#include <random>

struct MetalLamportContext {
    id<MTLDevice> device;
    id<MTLCommandQueue> commandQueue;
    id<MTLLibrary> library;
    id<MTLComputePipelineState> sha256Pipeline;
    id<MTLComputePipelineState> batchHashPipeline;
    std::mutex contextMutex;
};

// Embedded Metal shader for parallel hashing
static const char* lamportShaderSource = R"(
#include <metal_stdlib>
using namespace metal;

// SHA-256 constants
constant uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint rotr(uint x, uint n) {
    return (x >> n) | (x << (32 - n));
}

uint ch(uint x, uint y, uint z) {
    return (x & y) ^ (~x & z);
}

uint maj(uint x, uint y, uint z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint sigma0(uint x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

uint sigma1(uint x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

uint gamma0(uint x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

uint gamma1(uint x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// Hash a single 32-byte block (for Lamport key generation)
kernel void sha256_32byte_kernel(
    device const uchar* inputs [[buffer(0)]],
    device uchar* outputs [[buffer(1)]],
    uint tid [[thread_position_in_grid]]
) {
    // Initial hash values
    uint h0 = 0x6a09e667;
    uint h1 = 0xbb67ae85;
    uint h2 = 0x3c6ef372;
    uint h3 = 0xa54ff53a;
    uint h4 = 0x510e527f;
    uint h5 = 0x9b05688c;
    uint h6 = 0x1f83d9ab;
    uint h7 = 0x5be0cd19;
    
    // Load 32 bytes of input
    device const uchar* input = inputs + tid * 32;
    uint w[64];
    
    // First 8 words from input (32 bytes)
    for (int i = 0; i < 8; i++) {
        w[i] = ((uint)input[i*4] << 24) |
               ((uint)input[i*4+1] << 16) |
               ((uint)input[i*4+2] << 8) |
               ((uint)input[i*4+3]);
    }
    
    // Padding: 0x80 followed by zeros, then length
    w[8] = 0x80000000;
    for (int i = 9; i < 15; i++) w[i] = 0;
    w[15] = 256;  // Length in bits
    
    // Extend to 64 words
    for (int i = 16; i < 64; i++) {
        w[i] = gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16];
    }
    
    // Compression
    uint a = h0, b = h1, c = h2, d = h3;
    uint e = h4, f = h5, g = h6, h = h7;
    
    for (int i = 0; i < 64; i++) {
        uint t1 = h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
        uint t2 = sigma0(a) + maj(a, b, c);
        h = g; g = f; f = e;
        e = d + t1;
        d = c; c = b; b = a;
        a = t1 + t2;
    }
    
    h0 += a; h1 += b; h2 += c; h3 += d;
    h4 += e; h5 += f; h6 += g; h7 += h;
    
    // Write output
    device uchar* output = outputs + tid * 32;
    output[0] = h0 >> 24; output[1] = h0 >> 16; output[2] = h0 >> 8; output[3] = h0;
    output[4] = h1 >> 24; output[5] = h1 >> 16; output[6] = h1 >> 8; output[7] = h1;
    output[8] = h2 >> 24; output[9] = h2 >> 16; output[10] = h2 >> 8; output[11] = h2;
    output[12] = h3 >> 24; output[13] = h3 >> 16; output[14] = h3 >> 8; output[15] = h3;
    output[16] = h4 >> 24; output[17] = h4 >> 16; output[18] = h4 >> 8; output[19] = h4;
    output[20] = h5 >> 24; output[21] = h5 >> 16; output[22] = h5 >> 8; output[23] = h5;
    output[24] = h6 >> 24; output[25] = h6 >> 16; output[26] = h6 >> 8; output[27] = h6;
    output[28] = h7 >> 24; output[29] = h7 >> 16; output[30] = h7 >> 8; output[31] = h7;
}
)";

extern "C" {

bool metal_lamport_available(void) {
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    return device != nil;
}

MetalLamportContext* metal_lamport_init(void) {
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    if (!device) return nullptr;
    
    MetalLamportContext* ctx = new MetalLamportContext();
    ctx->device = device;
    ctx->commandQueue = [device newCommandQueue];
    
    NSError* error = nil;
    NSString* source = [NSString stringWithUTF8String:lamportShaderSource];
    ctx->library = [device newLibraryWithSource:source options:nil error:&error];
    
    if (error) {
        NSLog(@"Metal Lamport shader error: %@", error);
        delete ctx;
        return nullptr;
    }
    
    id<MTLFunction> hashFunc = [ctx->library newFunctionWithName:@"sha256_32byte_kernel"];
    ctx->sha256Pipeline = [device newComputePipelineStateWithFunction:hashFunc error:&error];
    
    return ctx;
}

void metal_lamport_destroy(MetalLamportContext* ctx) {
    if (ctx) delete ctx;
}

MetalLamportResult metal_lamport_keygen(
    MetalLamportContext* ctx,
    LamportHashFunc hash_func,
    uint8_t* privkey,
    uint8_t* pubkey,
    const uint8_t* seed
) {
    if (!ctx || !privkey || !pubkey) {
        return METAL_LAMPORT_ERROR_INVALID_INPUT;
    }
    
    std::lock_guard<std::mutex> lock(ctx->contextMutex);
    
    // Generate 512 random 32-byte values for private key
    size_t privkeySize = 512 * 32;
    
    if (seed) {
        // Deterministic generation from seed using SHA-256 chain
        uint8_t state[32];
        memcpy(state, seed, 32);
        for (int i = 0; i < 512; i++) {
            CC_SHA256(state, 32, privkey + i * 32);
            memcpy(state, privkey + i * 32, 32);
        }
    } else {
        // Random generation
        arc4random_buf(privkey, privkeySize);
    }
    
    // Hash each private key value to get public key using GPU
    id<MTLBuffer> privBuffer = [ctx->device newBufferWithBytes:privkey
                                                        length:privkeySize
                                                       options:MTLResourceStorageModeShared];
    id<MTLBuffer> pubBuffer = [ctx->device newBufferWithLength:privkeySize
                                                       options:MTLResourceStorageModeShared];
    
    id<MTLCommandBuffer> cmdBuffer = [ctx->commandQueue commandBuffer];
    id<MTLComputeCommandEncoder> encoder = [cmdBuffer computeCommandEncoder];
    
    [encoder setComputePipelineState:ctx->sha256Pipeline];
    [encoder setBuffer:privBuffer offset:0 atIndex:0];
    [encoder setBuffer:pubBuffer offset:0 atIndex:1];
    
    MTLSize gridSize = MTLSizeMake(512, 1, 1);
    MTLSize threadGroupSize = MTLSizeMake(MIN(512, 256), 1, 1);
    [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadGroupSize];
    
    [encoder endEncoding];
    [cmdBuffer commit];
    [cmdBuffer waitUntilCompleted];
    
    memcpy(pubkey, pubBuffer.contents, privkeySize);
    
    return METAL_LAMPORT_SUCCESS;
}

MetalLamportResult metal_lamport_batch_keygen(
    MetalLamportContext* ctx,
    LamportHashFunc hash_func,
    uint8_t* privkeys,
    uint8_t* pubkeys,
    const uint8_t* seeds,
    uint32_t count
) {
    if (!ctx || !privkeys || !pubkeys || count == 0) {
        return METAL_LAMPORT_ERROR_INVALID_INPUT;
    }
    
    std::lock_guard<std::mutex> lock(ctx->contextMutex);
    
    size_t keySize = 512 * 32;
    size_t totalSize = count * keySize;
    
    // Generate all private keys
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t* seed = seeds ? seeds + i * 32 : nullptr;
        if (seed) {
            uint8_t state[32];
            memcpy(state, seed, 32);
            for (int j = 0; j < 512; j++) {
                CC_SHA256(state, 32, privkeys + i * keySize + j * 32);
                memcpy(state, privkeys + i * keySize + j * 32, 32);
            }
        } else {
            arc4random_buf(privkeys + i * keySize, keySize);
        }
    }
    
    // Batch hash all private keys to get public keys
    uint32_t totalHashes = count * 512;
    
    id<MTLBuffer> privBuffer = [ctx->device newBufferWithBytes:privkeys
                                                        length:totalSize
                                                       options:MTLResourceStorageModeShared];
    id<MTLBuffer> pubBuffer = [ctx->device newBufferWithLength:totalSize
                                                       options:MTLResourceStorageModeShared];
    
    id<MTLCommandBuffer> cmdBuffer = [ctx->commandQueue commandBuffer];
    id<MTLComputeCommandEncoder> encoder = [cmdBuffer computeCommandEncoder];
    
    [encoder setComputePipelineState:ctx->sha256Pipeline];
    [encoder setBuffer:privBuffer offset:0 atIndex:0];
    [encoder setBuffer:pubBuffer offset:0 atIndex:1];
    
    MTLSize gridSize = MTLSizeMake(totalHashes, 1, 1);
    MTLSize threadGroupSize = MTLSizeMake(MIN(totalHashes, 256), 1, 1);
    [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadGroupSize];
    
    [encoder endEncoding];
    [cmdBuffer commit];
    [cmdBuffer waitUntilCompleted];
    
    memcpy(pubkeys, pubBuffer.contents, totalSize);
    
    return METAL_LAMPORT_SUCCESS;
}

MetalLamportResult metal_lamport_sign(
    MetalLamportContext* ctx,
    LamportHashFunc hash_func,
    uint8_t* signature,
    const uint8_t* privkey,
    const uint8_t* message_hash
) {
    if (!ctx || !signature || !privkey || !message_hash) {
        return METAL_LAMPORT_ERROR_INVALID_INPUT;
    }
    
    // For each bit of message hash, select corresponding private key half
    for (int i = 0; i < 256; i++) {
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        int bit = (message_hash[byte_idx] >> bit_idx) & 1;
        
        // Select private key value based on bit
        const uint8_t* selected = privkey + (i * 2 + bit) * 32;
        memcpy(signature + i * 32, selected, 32);
    }
    
    return METAL_LAMPORT_SUCCESS;
}

MetalLamportResult metal_lamport_verify(
    MetalLamportContext* ctx,
    LamportHashFunc hash_func,
    const uint8_t* pubkey,
    const uint8_t* signature,
    const uint8_t* message_hash
) {
    if (!ctx || !pubkey || !signature || !message_hash) {
        return METAL_LAMPORT_ERROR_INVALID_INPUT;
    }
    
    std::lock_guard<std::mutex> lock(ctx->contextMutex);
    
    // Hash each signature component
    id<MTLBuffer> sigBuffer = [ctx->device newBufferWithBytes:signature
                                                       length:256 * 32
                                                      options:MTLResourceStorageModeShared];
    id<MTLBuffer> hashBuffer = [ctx->device newBufferWithLength:256 * 32
                                                        options:MTLResourceStorageModeShared];
    
    id<MTLCommandBuffer> cmdBuffer = [ctx->commandQueue commandBuffer];
    id<MTLComputeCommandEncoder> encoder = [cmdBuffer computeCommandEncoder];
    
    [encoder setComputePipelineState:ctx->sha256Pipeline];
    [encoder setBuffer:sigBuffer offset:0 atIndex:0];
    [encoder setBuffer:hashBuffer offset:0 atIndex:1];
    
    MTLSize gridSize = MTLSizeMake(256, 1, 1);
    MTLSize threadGroupSize = MTLSizeMake(256, 1, 1);
    [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadGroupSize];
    
    [encoder endEncoding];
    [cmdBuffer commit];
    [cmdBuffer waitUntilCompleted];
    
    // Verify each hashed signature component matches public key
    uint8_t* hashes = (uint8_t*)hashBuffer.contents;
    
    for (int i = 0; i < 256; i++) {
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        int bit = (message_hash[byte_idx] >> bit_idx) & 1;
        
        const uint8_t* expected = pubkey + (i * 2 + bit) * 32;
        if (memcmp(hashes + i * 32, expected, 32) != 0) {
            return METAL_LAMPORT_ERROR_VERIFY_FAILED;
        }
    }
    
    return METAL_LAMPORT_SUCCESS;
}

MetalLamportResult metal_lamport_batch_verify(
    MetalLamportContext* ctx,
    LamportHashFunc hash_func,
    const uint8_t* pubkeys,
    const uint8_t* signatures,
    const uint8_t* message_hashes,
    uint32_t count,
    bool* results
) {
    if (!ctx || !pubkeys || !signatures || !message_hashes || !results || count == 0) {
        return METAL_LAMPORT_ERROR_INVALID_INPUT;
    }
    
    std::lock_guard<std::mutex> lock(ctx->contextMutex);
    
    size_t sigSize = 256 * 32;
    size_t pubSize = 512 * 32;
    uint32_t totalHashes = count * 256;
    
    // Batch hash all signatures
    id<MTLBuffer> sigBuffer = [ctx->device newBufferWithBytes:signatures
                                                       length:count * sigSize
                                                      options:MTLResourceStorageModeShared];
    id<MTLBuffer> hashBuffer = [ctx->device newBufferWithLength:count * sigSize
                                                        options:MTLResourceStorageModeShared];
    
    id<MTLCommandBuffer> cmdBuffer = [ctx->commandQueue commandBuffer];
    id<MTLComputeCommandEncoder> encoder = [cmdBuffer computeCommandEncoder];
    
    [encoder setComputePipelineState:ctx->sha256Pipeline];
    [encoder setBuffer:sigBuffer offset:0 atIndex:0];
    [encoder setBuffer:hashBuffer offset:0 atIndex:1];
    
    MTLSize gridSize = MTLSizeMake(totalHashes, 1, 1);
    MTLSize threadGroupSize = MTLSizeMake(MIN(totalHashes, 256), 1, 1);
    [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadGroupSize];
    
    [encoder endEncoding];
    [cmdBuffer commit];
    [cmdBuffer waitUntilCompleted];
    
    // Verify each signature
    uint8_t* hashes = (uint8_t*)hashBuffer.contents;
    
    for (uint32_t s = 0; s < count; s++) {
        results[s] = true;
        const uint8_t* msg_hash = message_hashes + s * 32;
        const uint8_t* pubkey = pubkeys + s * pubSize;
        uint8_t* sig_hashes = hashes + s * sigSize;
        
        for (int i = 0; i < 256 && results[s]; i++) {
            int byte_idx = i / 8;
            int bit_idx = 7 - (i % 8);
            int bit = (msg_hash[byte_idx] >> bit_idx) & 1;
            
            const uint8_t* expected = pubkey + (i * 2 + bit) * 32;
            if (memcmp(sig_hashes + i * 32, expected, 32) != 0) {
                results[s] = false;
            }
        }
    }
    
    return METAL_LAMPORT_SUCCESS;
}

} // extern "C"

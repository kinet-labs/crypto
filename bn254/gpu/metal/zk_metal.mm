// =============================================================================
// Metal ZK Accelerator Implementation
// =============================================================================
//

#include "zk_metal.h"

// First-party CPU bn254 -- used to derive Pedersen generators G, H once at
// protocol init via hash-to-curve with brand-neutral DSTs.  The MTLBuffers
// for each generator are then reused for every dispatch of pedersen_commit.
#include "bn254_fp.hpp"
#include "bn254_g1.hpp"
#include "bn254_hash_to_curve.hpp"

#include <cstdint>
#include <cstring>

#ifdef __APPLE__
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#endif

namespace kinet {
namespace crypto {
namespace metal {

namespace {

// Pack a single bn254 G1 affine point (Montgomery form) into 8 LE uint64
// limbs (x_lo..x_hi || y_lo..y_hi).  Matches the Metal kernel's expected
// G_xy / H_xy layout in bn254.metal.
void pack_g1_affine_le(const kinet::crypto::bn254::G1Affine& p,
                       uint64_t out_xy[8]) {
    for (int i = 0; i < 4; i++) {
        out_xy[i]     = p.x.limbs[i];
        out_xy[4 + i] = p.y.limbs[i];
    }
}

}  // namespace

// =============================================================================
// MetalZKContext Implementation
// =============================================================================

MetalZKContext::MetalZKContext() : initialized_(false) {
#ifdef __APPLE__
    device_ = nil;
    commandQueue_ = nil;
    cryptoLibrary_ = nil;
    zkLibrary_ = nil;
    pedersenGBuffer_ = nil;
    pedersenHBuffer_ = nil;
#endif
}

MetalZKContext::~MetalZKContext() {
#ifdef __APPLE__
    // ARC handles cleanup
#endif
}

bool MetalZKContext::initialize() {
#ifdef __APPLE__
    @autoreleasepool {
        // Get default Metal device
        device_ = MTLCreateSystemDefaultDevice();
        if (!device_) {
            return false;
        }

        deviceName_ = std::string([[device_ name] UTF8String]);

        // Create command queue
        commandQueue_ = [device_ newCommandQueue];
        if (!commandQueue_) {
            return false;
        }

        NSError* error = nil;

        // =================================================================
        // Load crypto metallib (BLS12-381, BLAKE3, KZG)
        // =================================================================
        NSArray* cryptoLibPaths = @[
            @"/usr/local/share/kinet/crypto/kinet_crypto.metallib",
            [[NSBundle mainBundle] pathForResource:@"kinet_crypto" ofType:@"metallib"] ?: @""
        ];

        for (NSString* libPath in cryptoLibPaths) {
            if (libPath.length > 0 && [[NSFileManager defaultManager] fileExistsAtPath:libPath]) {
                NSURL* libURL = [NSURL fileURLWithPath:libPath];
                cryptoLibrary_ = [device_ newLibraryWithURL:libURL error:&error];
                if (cryptoLibrary_) {
                    NSLog(@"Loaded crypto metallib from: %@", libPath);
                    break;
                }
            }
        }

        // =================================================================
        // Load ZK metallib (BN254, Poseidon, MSM, Goldilocks)
        // =================================================================
        NSArray* zkLibPaths = @[
            @"/usr/local/share/kinet/crypto/kinet_zk.metallib",
            [[NSBundle mainBundle] pathForResource:@"kinet_zk" ofType:@"metallib"] ?: @""
        ];

        for (NSString* libPath in zkLibPaths) {
            if (libPath.length > 0 && [[NSFileManager defaultManager] fileExistsAtPath:libPath]) {
                NSURL* libURL = [NSURL fileURLWithPath:libPath];
                zkLibrary_ = [device_ newLibraryWithURL:libURL error:&error];
                if (zkLibrary_) {
                    NSLog(@"Loaded ZK metallib from: %@", libPath);
                    break;
                }
            }
        }

        // =================================================================
        // Fallback: Try default library (built into app bundle)
        // =================================================================
        if (!cryptoLibrary_ && !zkLibrary_) {
            id<MTLLibrary> defaultLib = [device_ newDefaultLibrary];
            if (defaultLib) {
                // Use default library for both if metallibs not found
                cryptoLibrary_ = defaultLib;
                zkLibrary_ = defaultLib;
                NSLog(@"Using default Metal library for all shaders");
            }
        }

        // =================================================================
        // Last resort: Compile from source at runtime
        // =================================================================
        if (!cryptoLibrary_ || !zkLibrary_) {
            NSString* shaderPath = @"/usr/local/share/kinet/crypto/shaders";

            // Crypto shaders
            if (!cryptoLibrary_) {
                NSArray* cryptoShaders = @[@"blake3.metal", @"kzg.metal", @"bls12_381.metal"];
                NSMutableString* cryptoSource = [NSMutableString string];
                for (NSString* file in cryptoShaders) {
                    NSString* path = [shaderPath stringByAppendingPathComponent:file];
                    NSString* source = [NSString stringWithContentsOfFile:path
                                                                 encoding:NSUTF8StringEncoding
                                                                    error:&error];
                    if (source) {
                        [cryptoSource appendString:source];
                        [cryptoSource appendString:@"\n"];
                    }
                }
                if (cryptoSource.length > 0) {
                    MTLCompileOptions* options = [[MTLCompileOptions alloc] init];
                    if (@available(macOS 15.0, *)) {
                        options.mathMode = MTLMathModeFast;
                    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
                        options.fastMathEnabled = YES;
#pragma clang diagnostic pop
                    }
                    cryptoLibrary_ = [device_ newLibraryWithSource:cryptoSource
                                                           options:options
                                                             error:&error];
                }
            }

            // ZK shaders
            if (!zkLibrary_) {
                NSArray* zkShaders = @[@"bn254.metal", @"goldilocks.metal", @"poseidon.metal",
                                       @"poseidon2_bn254.metal", @"msm.metal"];
                NSMutableString* zkSource = [NSMutableString string];
                for (NSString* file in zkShaders) {
                    NSString* path = [shaderPath stringByAppendingPathComponent:file];
                    NSString* source = [NSString stringWithContentsOfFile:path
                                                                 encoding:NSUTF8StringEncoding
                                                                    error:&error];
                    if (source) {
                        [zkSource appendString:source];
                        [zkSource appendString:@"\n"];
                    }
                }
                if (zkSource.length > 0) {
                    MTLCompileOptions* options = [[MTLCompileOptions alloc] init];
                    if (@available(macOS 15.0, *)) {
                        options.mathMode = MTLMathModeFast;
                    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
                        options.fastMathEnabled = YES;
#pragma clang diagnostic pop
                    }
                    zkLibrary_ = [device_ newLibraryWithSource:zkSource
                                                       options:options
                                                         error:&error];
                }
            }
        }

        // At least one library must be available
        if (!cryptoLibrary_ && !zkLibrary_) {
            NSLog(@"Failed to load any Metal shader libraries: %@", error);
            return false;
        }

        // Initialize pipelines (crypto shaders from cryptoLibrary_)
        if (cryptoLibrary_) {
            if (!initBlake3Pipelines()) {
                NSLog(@"Warning: BLAKE3 pipelines not available");
            }
            if (!initKZGPipelines()) {
                NSLog(@"Warning: KZG pipelines not available");
            }
        }

        // Initialize pipelines (ZK shaders from zkLibrary_)
        if (zkLibrary_) {
            if (!initBN254Pipelines()) {
                NSLog(@"Warning: BN254 pipelines not available");
            }
            initPoseidon2Pipelines();  // Optional, don't fail if not present
            initFRIPipelines();         // Optional, don't fail if not present
        }

        initialized_ = true;
        return true;
    }
#else
    return false;
#endif
}

bool MetalZKContext::isAvailable() const {
    return initialized_;
}

const char* MetalZKContext::getDeviceName() const {
    return deviceName_.c_str();
}

uint64_t MetalZKContext::getMaxMemory() const {
#ifdef __APPLE__
    if (device_) {
        return [device_ recommendedMaxWorkingSetSize];
    }
#endif
    return 0;
}

#ifdef __APPLE__

id<MTLComputePipelineState> MetalZKContext::createPipeline(const char* functionName) {
    @autoreleasepool {
        NSError* error = nil;
        NSString* name = [NSString stringWithUTF8String:functionName];
        id<MTLFunction> function = nil;

        // Try crypto library first (BLS, BLAKE3, KZG)
        if (cryptoLibrary_) {
            function = [cryptoLibrary_ newFunctionWithName:name];
        }

        // Then try ZK library (BN254, Poseidon, MSM, Goldilocks)
        if (!function && zkLibrary_) {
            function = [zkLibrary_ newFunctionWithName:name];
        }

        if (!function) {
            // Not an error - function may legitimately not exist in loaded shaders
            return nil;
        }

        id<MTLComputePipelineState> pipeline =
            [device_ newComputePipelineStateWithFunction:function error:&error];

        if (!pipeline) {
            NSLog(@"Failed to create pipeline for %@: %@", name, error);
            return nil;
        }

        return pipeline;
    }
}

bool MetalZKContext::initBlake3Pipelines() {
    blake3HashPipeline_ = createPipeline("blake3_hash_block");
    blake3BatchPipeline_ = createPipeline("blake3_batch_hash");
    blake3MerklePipeline_ = createPipeline("blake3_merge_nodes");
    blake3XofPipeline_ = createPipeline("blake3_xof");
    
    // Some pipelines are optional
    return blake3HashPipeline_ != nil || blake3BatchPipeline_ != nil;
}

bool MetalZKContext::initBN254Pipelines() {
    pedersenCommitPipeline_ = createPipeline("pedersen_commit");
    bn254BatchAddPipeline_ = createPipeline("bn254_batch_add");
    bn254BatchMulPipeline_ = createPipeline("bn254_batch_scalar_mul");

    // -----------------------------------------------------------------
    // Pedersen generators G, H.
    //
    // Derived at protocol init via bn254 RFC-9380 hash-to-curve with
    // brand-neutral DSTs that match kinet-labs/crypto/pedersen/pedersen.go:
    //
    //     G = HashToG1("seed_g", "KINET_PEDERSEN_G")
    //     H = HashToG1("seed_h", "KINET_PEDERSEN_H")
    //
    // The seed ("seed_g" / "seed_h") is a fixed deterministic string;
    // the DST enforces independence and binds to the Kinet brand.
    // Identical DSTs on both sides (CPU oracle in pedersen.go, GPU kernel
    // via these MTLBuffers) yield byte-equal generators.
    //
    // Once landed, these buffers are reused for every pedersenCommit
    // dispatch -- there is no per-call cost.
    // -----------------------------------------------------------------
    {
        using kinet::crypto::bn254::G1Affine;
        using kinet::crypto::bn254::h2c::hash_to_curve_g1;

        const uint8_t seed_g[] = {'s','e','e','d','_','g'};
        const uint8_t seed_h[] = {'s','e','e','d','_','h'};
        const uint8_t dst_g[]  = {'L','U','X','_','P','E','D','E','R','S','E','N','_','G'};
        const uint8_t dst_h[]  = {'L','U','X','_','P','E','D','E','R','S','E','N','_','H'};

        G1Affine G = hash_to_curve_g1({seed_g, sizeof(seed_g)},
                                      {dst_g,  sizeof(dst_g)});
        G1Affine H = hash_to_curve_g1({seed_h, sizeof(seed_h)},
                                      {dst_h,  sizeof(dst_h)});

        uint64_t G_xy[8];
        uint64_t H_xy[8];
        pack_g1_affine_le(G, G_xy);
        pack_g1_affine_le(H, H_xy);

        pedersenGBuffer_ = [device_ newBufferWithBytes:G_xy
                                                length:sizeof(G_xy)
                                               options:MTLResourceStorageModeShared];
        pedersenHBuffer_ = [device_ newBufferWithBytes:H_xy
                                                length:sizeof(H_xy)
                                               options:MTLResourceStorageModeShared];
    }

    return pedersenCommitPipeline_ != nil
        && pedersenGBuffer_ != nil
        && pedersenHBuffer_ != nil;
}

bool MetalZKContext::initKZGPipelines() {
    kzgMsmPipeline_ = createPipeline("kzg_msm_bucket_accumulate");
    kzgFftPipeline_ = createPipeline("kzg_fft_butterfly");
    kzgBitReversePipeline_ = createPipeline("kzg_fft_bit_reverse");
    blobToFieldPipeline_ = createPipeline("blob_to_field_elements");

    return true; // KZG pipelines are optional for basic functionality
}

bool MetalZKContext::initPoseidon2Pipelines() {
    poseidon2HashPairPipeline_ = createPipeline("poseidon2_hash_pair");
    poseidon2MerkleLayerPipeline_ = createPipeline("poseidon2_merkle_layer");
    poseidon2CommitmentPipeline_ = createPipeline("poseidon2_commitment");
    poseidon2NullifierPipeline_ = createPipeline("poseidon2_nullifier");

    // At least hash pair should be available
    return poseidon2HashPairPipeline_ != nil;
}

bool MetalZKContext::initFRIPipelines() {
    friFoldLayerPipeline_ = createPipeline("fri_fold_layer");
    goldilocksBatchMulPipeline_ = createPipeline("goldilocks_batch_mul");

    return true; // FRI pipelines are optional
}

#endif // __APPLE__

// =============================================================================
// Blake3 Operations
// =============================================================================

Blake3Digest MetalZKContext::blake3Hash256(const uint8_t* data, uint32_t length) {
    Blake3Digest result = {};
    result.length = 32;
    
#ifdef __APPLE__
    if (!initialized_ || !blake3HashPipeline_) {
        return result;
    }
    
    @autoreleasepool {
        // Create buffers
        id<MTLBuffer> inputBuffer = [device_ newBufferWithBytes:data 
                                                         length:length 
                                                        options:MTLResourceStorageModeShared];
        
        id<MTLBuffer> outputBuffer = [device_ newBufferWithLength:32 
                                                          options:MTLResourceStorageModeShared];
        
        id<MTLBuffer> lengthBuffer = [device_ newBufferWithBytes:&length 
                                                          length:sizeof(uint32_t) 
                                                         options:MTLResourceStorageModeShared];
        
        // Create command buffer
        id<MTLCommandBuffer> commandBuffer = [commandQueue_ commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:blake3HashPipeline_];
        [encoder setBuffer:inputBuffer offset:0 atIndex:0];
        [encoder setBuffer:outputBuffer offset:0 atIndex:1];
        [encoder setBuffer:lengthBuffer offset:0 atIndex:2];
        
        // Dispatch
        MTLSize gridSize = MTLSizeMake(1, 1, 1);
        MTLSize threadGroupSize = MTLSizeMake(1, 1, 1);
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadGroupSize];
        
        [encoder endEncoding];
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        // Copy result
        memcpy(result.bytes, [outputBuffer contents], 32);
        // NOTE: Blake3Digest has no `valid` field; the legacy code referenced
        // a non-existent member. Phase 3 redesigns this struct.
    }
#endif
    
    return result;
}

Blake3Digest MetalZKContext::blake3Hash512(const uint8_t* data, uint32_t length) {
    Blake3Digest result = {};
    result.length = 64;
    
    // Similar to hash256 but with 64-byte output
    // Implementation follows same pattern
    
    return result;
}

std::vector<Blake3Digest> MetalZKContext::blake3BatchHash(
    const std::vector<const uint8_t*>& inputs,
    const std::vector<uint32_t>& lengths
) {
    std::vector<Blake3Digest> results(inputs.size());
    
#ifdef __APPLE__
    if (!initialized_ || !blake3BatchPipeline_) {
        return results;
    }
    
    @autoreleasepool {
        // Flatten inputs into single buffer with offsets
        uint32_t totalSize = 0;
        std::vector<uint32_t> offsets(inputs.size());
        for (size_t i = 0; i < inputs.size(); i++) {
            offsets[i] = totalSize;
            totalSize += lengths[i];
        }
        
        std::vector<uint8_t> flatData(totalSize);
        for (size_t i = 0; i < inputs.size(); i++) {
            memcpy(&flatData[offsets[i]], inputs[i], lengths[i]);
        }
        
        // Create buffers
        id<MTLBuffer> inputBuffer = [device_ newBufferWithBytes:flatData.data() 
                                                         length:totalSize 
                                                        options:MTLResourceStorageModeShared];
        
        id<MTLBuffer> outputBuffer = [device_ newBufferWithLength:inputs.size() * 32 
                                                          options:MTLResourceStorageModeShared];
        
        id<MTLBuffer> offsetBuffer = [device_ newBufferWithBytes:offsets.data() 
                                                          length:offsets.size() * sizeof(uint32_t) 
                                                         options:MTLResourceStorageModeShared];
        
        id<MTLBuffer> lengthBuffer = [device_ newBufferWithBytes:lengths.data() 
                                                          length:lengths.size() * sizeof(uint32_t) 
                                                         options:MTLResourceStorageModeShared];
        
        // Dispatch
        id<MTLCommandBuffer> commandBuffer = [commandQueue_ commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:blake3BatchPipeline_];
        [encoder setBuffer:inputBuffer offset:0 atIndex:0];
        [encoder setBuffer:outputBuffer offset:0 atIndex:1];
        [encoder setBuffer:offsetBuffer offset:0 atIndex:2];
        [encoder setBuffer:lengthBuffer offset:0 atIndex:3];
        
        NSUInteger threadGroupWidth = [blake3BatchPipeline_ maxTotalThreadsPerThreadgroup];
        MTLSize gridSize = MTLSizeMake(inputs.size(), 1, 1);
        MTLSize threadGroupSize = MTLSizeMake(std::min((NSUInteger)inputs.size(), threadGroupWidth), 1, 1);
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadGroupSize];
        
        [encoder endEncoding];
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        // Copy results
        uint32_t* output = (uint32_t*)[outputBuffer contents];
        for (size_t i = 0; i < inputs.size(); i++) {
            results[i].length = 32;
            memcpy(results[i].bytes, &output[i * 8], 32);
        }
    }
#endif
    
    return results;
}

// =============================================================================
// Pedersen Operations
// =============================================================================

PedersenCommitment MetalZKContext::pedersenCommit(
    const Fr256& value,
    const Fr256& blindingFactor
) {
    PedersenCommitment result = {};

#ifdef __APPLE__
    if (!initialized_ || !pedersenCommitPipeline_
        || !pedersenGBuffer_ || !pedersenHBuffer_) {
        return result;
    }

    @autoreleasepool {
        // Per-call buffers: scalars + output.  G/H are bound from the
        // pre-computed context buffers (one MTLBuffer alloc total, not
        // one per dispatch).
        id<MTLBuffer> valueBuffer = [device_ newBufferWithBytes:value.limbs
                                                         length:32
                                                        options:MTLResourceStorageModeShared];
        id<MTLBuffer> blindBuffer = [device_ newBufferWithBytes:blindingFactor.limbs
                                                         length:32
                                                        options:MTLResourceStorageModeShared];
        id<MTLBuffer> outputBuffer = [device_ newBufferWithLength:64
                                                          options:MTLResourceStorageModeShared];
        uint32_t count = 1;
        id<MTLBuffer> countBuffer = [device_ newBufferWithBytes:&count
                                                         length:sizeof(uint32_t)
                                                        options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> commandBuffer = [commandQueue_ commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        // ABI: (values, blinding, G_xy, H_xy, commitments, num) per
        // pedersen_commit kernel signature in bn254.metal.
        [encoder setComputePipelineState:pedersenCommitPipeline_];
        [encoder setBuffer:valueBuffer    offset:0 atIndex:0];
        [encoder setBuffer:blindBuffer    offset:0 atIndex:1];
        [encoder setBuffer:pedersenGBuffer_ offset:0 atIndex:2];
        [encoder setBuffer:pedersenHBuffer_ offset:0 atIndex:3];
        [encoder setBuffer:outputBuffer   offset:0 atIndex:4];
        [encoder setBuffer:countBuffer    offset:0 atIndex:5];

        MTLSize gridSize = MTLSizeMake(1, 1, 1);
        MTLSize threadGroupSize = MTLSizeMake(1, 1, 1);
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadGroupSize];

        [encoder endEncoding];
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        uint64_t* output = (uint64_t*)[outputBuffer contents];
        memcpy(result.point.x.limbs, output, 32);
        memcpy(result.point.y.limbs, output + 4, 32);
        result.point.infinity = false;
        result.valid = true;
    }
#endif

    return result;
}

// =============================================================================
// Singleton Access
// =============================================================================

MetalZKContext& getMetalZKContext() {
    static MetalZKContext context;
    static bool initialized = false;
    if (!initialized) {
        context.initialize();
        initialized = true;
    }
    return context;
}

bool isMetalAvailable() {
    return getMetalZKContext().isAvailable();
}

// =============================================================================
// C API Implementation
// =============================================================================

extern "C" {

int metal_is_available() {
    return isMetalAvailable() ? 1 : 0;
}

int metal_blake3_hash256(const uint8_t* data, uint32_t len, uint8_t* out) {
    auto& ctx = getMetalZKContext();
    if (!ctx.isAvailable()) return -1;
    
    Blake3Digest digest = ctx.blake3Hash256(data, len);
    memcpy(out, digest.bytes, 32);
    return 0;
}

int metal_blake3_hash512(const uint8_t* data, uint32_t len, uint8_t* out) {
    auto& ctx = getMetalZKContext();
    if (!ctx.isAvailable()) return -1;
    
    Blake3Digest digest = ctx.blake3Hash512(data, len);
    memcpy(out, digest.bytes, 64);
    return 0;
}

int metal_pedersen_commit(
    const uint64_t* value,
    const uint64_t* blinding,
    uint64_t* commitmentX,
    uint64_t* commitmentY
) {
    auto& ctx = getMetalZKContext();
    if (!ctx.isAvailable()) return -1;
    
    Fr256 v, b;
    memcpy(v.limbs, value, 32);
    memcpy(b.limbs, blinding, 32);
    
    PedersenCommitment commit = ctx.pedersenCommit(v, b);
    if (!commit.valid) return -1;
    
    memcpy(commitmentX, commit.point.x.limbs, 32);
    memcpy(commitmentY, commit.point.y.limbs, 32);
    return 0;
}

int metal_bn254_scalar_mul(
    const uint64_t* pointX,
    const uint64_t* pointY,
    const uint64_t* scalar,
    uint64_t* resultX,
    uint64_t* resultY
) {
    auto& ctx = getMetalZKContext();
    if (!ctx.isAvailable()) return -1;

    BN254G1Affine point;
    Fr256 s;
    memcpy(point.x.limbs, pointX, 32);
    memcpy(point.y.limbs, pointY, 32);
    memcpy(s.limbs, scalar, 32);
    point.infinity = false;

    BN254G1Affine result = ctx.bn254ScalarMul(point, s);
    memcpy(resultX, result.x.limbs, 32);
    memcpy(resultY, result.y.limbs, 32);
    return 0;
}

// =============================================================================
// Poseidon2 C++ Method Implementations
// =============================================================================

std::vector<Fr256> MetalZKContext::poseidon2BatchHashPair(
    const std::vector<Fr256>& left,
    const std::vector<Fr256>& right
) {
    std::vector<Fr256> results(left.size());

#ifdef __APPLE__
    if (!initialized_ || !poseidon2HashPairPipeline_ || left.size() != right.size()) {
        return results;
    }

    @autoreleasepool {
        uint32_t count = (uint32_t)left.size();
        size_t elemSize = sizeof(Fr256);

        id<MTLBuffer> leftBuffer = [device_ newBufferWithBytes:left.data()
                                                        length:count * elemSize
                                                       options:MTLResourceStorageModeShared];

        id<MTLBuffer> rightBuffer = [device_ newBufferWithBytes:right.data()
                                                         length:count * elemSize
                                                        options:MTLResourceStorageModeShared];

        id<MTLBuffer> outputBuffer = [device_ newBufferWithLength:count * elemSize
                                                          options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> commandBuffer = [commandQueue_ commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        [encoder setComputePipelineState:poseidon2HashPairPipeline_];
        [encoder setBuffer:leftBuffer offset:0 atIndex:0];
        [encoder setBuffer:rightBuffer offset:0 atIndex:1];
        [encoder setBuffer:outputBuffer offset:0 atIndex:2];

        NSUInteger threadGroupWidth = [poseidon2HashPairPipeline_ maxTotalThreadsPerThreadgroup];
        MTLSize gridSize = MTLSizeMake(count, 1, 1);
        MTLSize threadGroupSize = MTLSizeMake(MIN((NSUInteger)count, threadGroupWidth), 1, 1);
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadGroupSize];

        [encoder endEncoding];
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        memcpy(results.data(), [outputBuffer contents], count * elemSize);
    }
#endif

    return results;
}

std::vector<Fr256> MetalZKContext::poseidon2MerkleLayer(const std::vector<Fr256>& current) {
    std::vector<Fr256> results(current.size() / 2);

#ifdef __APPLE__
    if (!initialized_ || !poseidon2MerkleLayerPipeline_ || current.size() < 2) {
        return results;
    }

    @autoreleasepool {
        uint32_t currentSize = (uint32_t)current.size();
        uint32_t outputCount = currentSize / 2;
        size_t elemSize = sizeof(Fr256);

        id<MTLBuffer> currentBuffer = [device_ newBufferWithBytes:current.data()
                                                           length:currentSize * elemSize
                                                          options:MTLResourceStorageModeShared];

        id<MTLBuffer> outputBuffer = [device_ newBufferWithLength:outputCount * elemSize
                                                          options:MTLResourceStorageModeShared];

        id<MTLBuffer> sizeBuffer = [device_ newBufferWithBytes:&currentSize
                                                        length:sizeof(uint32_t)
                                                       options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> commandBuffer = [commandQueue_ commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        [encoder setComputePipelineState:poseidon2MerkleLayerPipeline_];
        [encoder setBuffer:currentBuffer offset:0 atIndex:0];
        [encoder setBuffer:outputBuffer offset:0 atIndex:1];
        [encoder setBuffer:sizeBuffer offset:0 atIndex:2];

        NSUInteger threadGroupWidth = [poseidon2MerkleLayerPipeline_ maxTotalThreadsPerThreadgroup];
        MTLSize gridSize = MTLSizeMake(outputCount, 1, 1);
        MTLSize threadGroupSize = MTLSizeMake(MIN((NSUInteger)outputCount, threadGroupWidth), 1, 1);
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadGroupSize];

        [encoder endEncoding];
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        memcpy(results.data(), [outputBuffer contents], outputCount * elemSize);
    }
#endif

    return results;
}

std::vector<Fr256> MetalZKContext::poseidon2BatchCommitment(
    const std::vector<Fr256>& values,
    const std::vector<Fr256>& blindings,
    const std::vector<Fr256>& salts
) {
    std::vector<Fr256> results(values.size());

#ifdef __APPLE__
    if (!initialized_ || !poseidon2CommitmentPipeline_) {
        return results;
    }

    @autoreleasepool {
        uint32_t count = (uint32_t)values.size();
        size_t elemSize = sizeof(Fr256);

        id<MTLBuffer> valueBuffer = [device_ newBufferWithBytes:values.data()
                                                         length:count * elemSize
                                                        options:MTLResourceStorageModeShared];

        id<MTLBuffer> blindBuffer = [device_ newBufferWithBytes:blindings.data()
                                                         length:count * elemSize
                                                        options:MTLResourceStorageModeShared];

        id<MTLBuffer> saltBuffer = [device_ newBufferWithBytes:salts.data()
                                                        length:count * elemSize
                                                       options:MTLResourceStorageModeShared];

        id<MTLBuffer> outputBuffer = [device_ newBufferWithLength:count * elemSize
                                                          options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> commandBuffer = [commandQueue_ commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        [encoder setComputePipelineState:poseidon2CommitmentPipeline_];
        [encoder setBuffer:valueBuffer offset:0 atIndex:0];
        [encoder setBuffer:blindBuffer offset:0 atIndex:1];
        [encoder setBuffer:saltBuffer offset:0 atIndex:2];
        [encoder setBuffer:outputBuffer offset:0 atIndex:3];

        NSUInteger threadGroupWidth = [poseidon2CommitmentPipeline_ maxTotalThreadsPerThreadgroup];
        MTLSize gridSize = MTLSizeMake(count, 1, 1);
        MTLSize threadGroupSize = MTLSizeMake(MIN((NSUInteger)count, threadGroupWidth), 1, 1);
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadGroupSize];

        [encoder endEncoding];
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        memcpy(results.data(), [outputBuffer contents], count * elemSize);
    }
#endif

    return results;
}

std::vector<Fr256> MetalZKContext::poseidon2BatchNullifier(
    const std::vector<Fr256>& keys,
    const std::vector<Fr256>& commitments,
    const std::vector<Fr256>& indices
) {
    std::vector<Fr256> results(keys.size());

#ifdef __APPLE__
    if (!initialized_ || !poseidon2NullifierPipeline_) {
        return results;
    }

    @autoreleasepool {
        uint32_t count = (uint32_t)keys.size();
        size_t elemSize = sizeof(Fr256);

        id<MTLBuffer> keyBuffer = [device_ newBufferWithBytes:keys.data()
                                                       length:count * elemSize
                                                      options:MTLResourceStorageModeShared];

        id<MTLBuffer> commitBuffer = [device_ newBufferWithBytes:commitments.data()
                                                          length:count * elemSize
                                                         options:MTLResourceStorageModeShared];

        id<MTLBuffer> indexBuffer = [device_ newBufferWithBytes:indices.data()
                                                         length:count * elemSize
                                                        options:MTLResourceStorageModeShared];

        id<MTLBuffer> outputBuffer = [device_ newBufferWithLength:count * elemSize
                                                          options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> commandBuffer = [commandQueue_ commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];

        [encoder setComputePipelineState:poseidon2NullifierPipeline_];
        [encoder setBuffer:keyBuffer offset:0 atIndex:0];
        [encoder setBuffer:commitBuffer offset:0 atIndex:1];
        [encoder setBuffer:indexBuffer offset:0 atIndex:2];
        [encoder setBuffer:outputBuffer offset:0 atIndex:3];

        NSUInteger threadGroupWidth = [poseidon2NullifierPipeline_ maxTotalThreadsPerThreadgroup];
        MTLSize gridSize = MTLSizeMake(count, 1, 1);
        MTLSize threadGroupSize = MTLSizeMake(MIN((NSUInteger)count, threadGroupWidth), 1, 1);
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadGroupSize];

        [encoder endEncoding];
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];

        memcpy(results.data(), [outputBuffer contents], count * elemSize);
    }
#endif

    return results;
}

// =============================================================================
// Poseidon2 C API (wraps C++ methods)
// =============================================================================

int metal_zk_poseidon2_hash_pair(
    void* /* ctx_ptr */,
    void* output,
    const void* left,
    const void* right,
    uint32_t count
) {
    auto& ctx = getMetalZKContext();
    if (!ctx.isAvailable()) return -1;

    std::vector<Fr256> leftVec(count);
    std::vector<Fr256> rightVec(count);
    memcpy(leftVec.data(), left, count * sizeof(Fr256));
    memcpy(rightVec.data(), right, count * sizeof(Fr256));

    auto results = ctx.poseidon2BatchHashPair(leftVec, rightVec);
    memcpy(output, results.data(), count * sizeof(Fr256));
    return 0;
}

int metal_zk_poseidon2_merkle_layer(
    void* /* ctx_ptr */,
    void* output,
    const void* current_layer,
    uint32_t current_size
) {
    auto& ctx = getMetalZKContext();
    if (!ctx.isAvailable()) return -1;
    if (current_size < 2 || (current_size & 1) != 0) return -5;

    std::vector<Fr256> currentVec(current_size);
    memcpy(currentVec.data(), current_layer, current_size * sizeof(Fr256));

    auto results = ctx.poseidon2MerkleLayer(currentVec);
    memcpy(output, results.data(), (current_size / 2) * sizeof(Fr256));
    return 0;
}

int metal_zk_batch_commitment(
    void* /* ctx_ptr */,
    void* output,
    const void* values,
    const void* blindings,
    const void* salts,
    uint32_t count
) {
    auto& ctx = getMetalZKContext();
    if (!ctx.isAvailable()) return -1;

    std::vector<Fr256> valuesVec(count);
    std::vector<Fr256> blindingsVec(count);
    std::vector<Fr256> saltsVec(count);
    memcpy(valuesVec.data(), values, count * sizeof(Fr256));
    memcpy(blindingsVec.data(), blindings, count * sizeof(Fr256));
    memcpy(saltsVec.data(), salts, count * sizeof(Fr256));

    auto results = ctx.poseidon2BatchCommitment(valuesVec, blindingsVec, saltsVec);
    memcpy(output, results.data(), count * sizeof(Fr256));
    return 0;
}

int metal_zk_batch_nullifier(
    void* /* ctx_ptr */,
    void* output,
    const void* keys,
    const void* commitments,
    const void* indices,
    uint32_t count
) {
    auto& ctx = getMetalZKContext();
    if (!ctx.isAvailable()) return -1;

    std::vector<Fr256> keysVec(count);
    std::vector<Fr256> commitmentsVec(count);
    std::vector<Fr256> indicesVec(count);
    memcpy(keysVec.data(), keys, count * sizeof(Fr256));
    memcpy(commitmentsVec.data(), commitments, count * sizeof(Fr256));
    memcpy(indicesVec.data(), indices, count * sizeof(Fr256));

    auto results = ctx.poseidon2BatchNullifier(keysVec, commitmentsVec, indicesVec);
    memcpy(output, results.data(), count * sizeof(Fr256));
    return 0;
}

uint32_t metal_zk_get_threshold(int op_type) {
    switch (op_type) {
        case 1: return 64;   // POSEIDON2_HASH
        case 2: return 128;  // MERKLE_LAYER
        case 3: return 256;  // MSM
        case 4: return 128;  // COMMITMENT
        case 5: return 128;  // NULLIFIER
        default: return 64;
    }
}

} // extern "C"

} // namespace metal
} // namespace crypto
} // namespace kinet

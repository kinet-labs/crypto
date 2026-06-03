// =============================================================================
// Metal ZK Accelerator Header
// =============================================================================
//
// C++ wrapper for Metal compute shaders for ZK cryptographic operations.
// Provides GPU-accelerated Pedersen, Blake3, KZG, and BN254 operations.
//
// Copyright (C) 2024-2025 Kinet Industries Inc.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <memory>

#ifdef __APPLE__
#include <Metal/Metal.h>
#include <MetalPerformanceShaders/MetalPerformanceShaders.h>
#endif

namespace kinet {
namespace crypto {
namespace metal {

// =============================================================================
// Type Definitions
// =============================================================================

// 256-bit field element (4 x 64-bit limbs)
struct Fr256 {
    uint64_t limbs[4];
};

// 384-bit field element (6 x 64-bit limbs)
struct Fp384 {
    uint64_t limbs[6];
};

// BN254 G1 affine point
struct BN254G1Affine {
    Fr256 x;
    Fr256 y;
    bool infinity;
};

// BLS12-381 G1 affine point
struct BLS12G1Affine {
    Fp384 x;
    Fp384 y;
    bool infinity;
};

// Pedersen commitment result
struct PedersenCommitment {
    BN254G1Affine point;
    bool valid;
};

// Blake3 hash output
struct Blake3Digest {
    uint8_t bytes[64];
    uint32_t length;
};

// KZG commitment
struct KZGCommitment {
    BLS12G1Affine point;
    bool valid;
};

// =============================================================================
// Metal Context
// =============================================================================

class MetalZKContext {
public:
    MetalZKContext();
    ~MetalZKContext();

    // Initialization
    bool initialize();
    bool isAvailable() const;
    
    // Device info
    const char* getDeviceName() const;
    uint64_t getMaxMemory() const;

    // =========================================================================
    // Blake3 Operations
    // =========================================================================
    
    // Hash single input
    Blake3Digest blake3Hash256(const uint8_t* data, uint32_t length);
    Blake3Digest blake3Hash512(const uint8_t* data, uint32_t length);
    
    // Batch hash multiple inputs
    std::vector<Blake3Digest> blake3BatchHash(
        const std::vector<const uint8_t*>& inputs,
        const std::vector<uint32_t>& lengths
    );
    
    // XOF (extendable output)
    std::vector<uint8_t> blake3XOF(
        const uint8_t* data,
        uint32_t inputLength,
        uint32_t outputLength
    );
    
    // Merkle tree root
    Blake3Digest blake3MerkleRoot(
        const std::vector<Blake3Digest>& leaves
    );

    // =========================================================================
    // BN254/Pedersen Operations
    // =========================================================================
    
    // Single Pedersen commitment
    PedersenCommitment pedersenCommit(
        const Fr256& value,
        const Fr256& blindingFactor
    );
    
    // Batch Pedersen commitments
    std::vector<PedersenCommitment> pedersenBatchCommit(
        const std::vector<Fr256>& values,
        const std::vector<Fr256>& blindingFactors
    );
    
    // BN254 scalar multiplication
    BN254G1Affine bn254ScalarMul(
        const BN254G1Affine& point,
        const Fr256& scalar
    );
    
    // BN254 batch scalar multiplication (MSM)
    std::vector<BN254G1Affine> bn254BatchScalarMul(
        const std::vector<BN254G1Affine>& points,
        const std::vector<Fr256>& scalars
    );
    
    // BN254 point addition
    BN254G1Affine bn254Add(
        const BN254G1Affine& a,
        const BN254G1Affine& b
    );

    // =========================================================================
    // KZG/BLS12-381 Operations
    // =========================================================================
    
    // Convert blob to polynomial coefficients
    std::vector<Fr256> blobToPolynomial(
        const uint8_t* blob,
        uint32_t blobSize
    );
    
    // Compute KZG commitment using MSM
    KZGCommitment kzgCommit(
        const std::vector<Fr256>& coefficients,
        const std::vector<BLS12G1Affine>& trustedSetup
    );
    
    // Compute KZG opening proof
    std::pair<KZGCommitment, Fr256> kzgComputeProof(
        const std::vector<Fr256>& polynomial,
        const Fr256& point,
        const std::vector<BLS12G1Affine>& trustedSetup
    );
    
    // FFT over scalar field
    std::vector<Fr256> fft(
        const std::vector<Fr256>& coefficients,
        bool inverse = false
    );
    
    // Inverse FFT
    std::vector<Fr256> ifft(const std::vector<Fr256>& values);

    // =========================================================================
    // Poseidon2 Operations (BN254/Fr)
    // =========================================================================

    // Hash pair (2-to-1 compression for Merkle trees)
    Fr256 poseidon2HashPair(const Fr256& left, const Fr256& right);

    // Batch hash pairs
    std::vector<Fr256> poseidon2BatchHashPair(
        const std::vector<Fr256>& left,
        const std::vector<Fr256>& right
    );

    // Merkle tree layer (hash adjacent pairs)
    std::vector<Fr256> poseidon2MerkleLayer(const std::vector<Fr256>& current);

    // Build complete Merkle tree
    std::vector<Fr256> poseidon2MerkleTree(const std::vector<Fr256>& leaves);

    // Compute commitment: Poseidon2(value, blinding, salt)
    Fr256 poseidon2Commitment(const Fr256& value, const Fr256& blinding, const Fr256& salt);

    // Compute nullifier: Poseidon2(key, commitment, index)
    Fr256 poseidon2Nullifier(const Fr256& key, const Fr256& commitment, const Fr256& index);

    // Batch commitments
    std::vector<Fr256> poseidon2BatchCommitment(
        const std::vector<Fr256>& values,
        const std::vector<Fr256>& blindings,
        const std::vector<Fr256>& salts
    );

    // Batch nullifiers
    std::vector<Fr256> poseidon2BatchNullifier(
        const std::vector<Fr256>& keys,
        const std::vector<Fr256>& commitments,
        const std::vector<Fr256>& indices
    );

    // =========================================================================
    // Goldilocks/FRI Operations (for STARK)
    // =========================================================================

    // FRI fold layer
    std::vector<uint64_t> friFoldLayer(
        const std::vector<uint64_t>& evals,
        uint64_t alpha,
        uint64_t omega_inv
    );

private:
#ifdef __APPLE__
    id<MTLDevice> device_;
    id<MTLCommandQueue> commandQueue_;
    id<MTLLibrary> cryptoLibrary_;  // kinet_crypto.metallib (BLS, BLAKE3, KZG)
    id<MTLLibrary> zkLibrary_;      // kinet_zk.metallib (BN254, Poseidon, MSM, Goldilocks)

    // Compute pipelines
    id<MTLComputePipelineState> blake3HashPipeline_;
    id<MTLComputePipelineState> blake3BatchPipeline_;
    id<MTLComputePipelineState> blake3MerklePipeline_;
    id<MTLComputePipelineState> blake3XofPipeline_;
    
    id<MTLComputePipelineState> pedersenCommitPipeline_;
    id<MTLComputePipelineState> bn254BatchAddPipeline_;
    id<MTLComputePipelineState> bn254BatchMulPipeline_;
    
    id<MTLComputePipelineState> kzgMsmPipeline_;
    id<MTLComputePipelineState> kzgFftPipeline_;
    id<MTLComputePipelineState> kzgBitReversePipeline_;
    id<MTLComputePipelineState> blobToFieldPipeline_;

    // Poseidon2 pipelines
    id<MTLComputePipelineState> poseidon2HashPairPipeline_;
    id<MTLComputePipelineState> poseidon2MerkleLayerPipeline_;
    id<MTLComputePipelineState> poseidon2CommitmentPipeline_;
    id<MTLComputePipelineState> poseidon2NullifierPipeline_;

    // FRI/Goldilocks pipelines
    id<MTLComputePipelineState> friFoldLayerPipeline_;
    id<MTLComputePipelineState> goldilocksBatchMulPipeline_;

    // Initialize compute pipelines
    bool initBlake3Pipelines();
    bool initBN254Pipelines();
    bool initKZGPipelines();
    bool initPoseidon2Pipelines();
    bool initFRIPipelines();

    // Helper to compile shader function
    id<MTLComputePipelineState> createPipeline(const char* functionName);
#endif
    
    bool initialized_;
    std::string deviceName_;
};

// =============================================================================
// Singleton Access
// =============================================================================

// Get global Metal context (lazy initialization)
MetalZKContext& getMetalZKContext();

// Check if Metal acceleration is available
bool isMetalAvailable();

// =============================================================================
// C API for CGO Bridge
// =============================================================================

extern "C" {

// Blake3
int metal_blake3_hash256(const uint8_t* data, uint32_t len, uint8_t* out);
int metal_blake3_hash512(const uint8_t* data, uint32_t len, uint8_t* out);
int metal_blake3_xof(const uint8_t* data, uint32_t inLen, uint8_t* out, uint32_t outLen);
int metal_blake3_merkle_root(const uint8_t* leaves, uint32_t numLeaves, uint8_t* out);

// Pedersen (BN254)
int metal_pedersen_commit(
    const uint64_t* value,
    const uint64_t* blinding,
    uint64_t* commitmentX,
    uint64_t* commitmentY
);

int metal_pedersen_batch_commit(
    const uint64_t* values,
    const uint64_t* blindings,
    uint32_t count,
    uint64_t* commitments
);

// BN254
int metal_bn254_scalar_mul(
    const uint64_t* pointX,
    const uint64_t* pointY,
    const uint64_t* scalar,
    uint64_t* resultX,
    uint64_t* resultY
);

int metal_bn254_add(
    const uint64_t* ax, const uint64_t* ay,
    const uint64_t* bx, const uint64_t* by,
    uint64_t* rx, uint64_t* ry
);

// KZG
int metal_kzg_commit(
    const uint64_t* coefficients,
    uint32_t numCoeffs,
    const uint64_t* trustedSetup,
    uint64_t* commitmentX,
    uint64_t* commitmentY
);

int metal_fft(
    uint64_t* coefficients,
    uint32_t n,
    int inverse
);

// Availability check
int metal_is_available();

} // extern "C"

} // namespace metal
} // namespace crypto
} // namespace kinet

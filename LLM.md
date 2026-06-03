# Kinet Crypto - Cryptographic Primitives

**Last Updated**: 2025-12-30
**Module**: `kinet-labs/crypto`
**Role**: GPU-accelerated cryptographic primitives

## Architecture Position

```
kinet-labs/gpu      ← Foundation (optional MLX backend)
    ▲
    │
kinet-labs/crypto   ← YOU ARE HERE (BLS, ML-DSA, hashing)
    │
    ▼
kinet-labs/lattice  ← NTT operations for ML-DSA
```

**Depends on:**
- `kinet-labs/lattice` (for ML-DSA NTT operations)
- `kinet-labs/gpu` (optional, for MLX backend)
- Metal framework (macOS, for BLS12-381 compute shaders)

## Overview

C++ library providing GPU-accelerated:
- **BLS12-381**: Pairing-based signatures with Metal compute shaders
- **ML-DSA**: Post-quantum signatures (Dilithium) with NTT acceleration
- **Hashing**: SHA3-256, SHA3-512, BLAKE3
- **Threshold**: Shamir secret sharing, threshold signatures

## GPU Acceleration

### Metal BLS12-381 Shaders (macOS)

Native Metal compute shaders for elliptic curve operations:

| Kernel | Description | Parallelism |
|--------|-------------|-------------|
| `g1_batch_add` | Parallel point addition | Per-point |
| `g1_batch_double` | Parallel point doubling | Per-point |
| `g1_batch_scalar_mul` | Parallel scalar multiplication | Per-point |
| `bls_batch_verify_msm` | Multi-scalar multiplication for batch verification | Threadgroup reduction |

**Performance target**: 8+ signatures for GPU dispatch (below that, CPU is faster).

### Architecture

```
bls12_381.metal     ← Metal compute shaders (G1 arithmetic)
    ↓
metal_bls.mm        ← Objective-C++ Metal API wrapper
    ↓
crypto.cpp          ← C++ API with automatic GPU dispatch
    ↓
crypto.h            ← Public C API
```

## Build

```bash
cd /Users/z/work/kinet-labs/crypto
mkdir -p build && cd build

# Metal BLS acceleration (recommended on macOS)
cmake -DWITH_METAL=ON ..
make -j$(sysctl -n hw.ncpu)

# With MLX GPU backend (requires kinet-labs/gpu built first)
cmake -DWITH_METAL=ON -DWITH_GPU=ON -DGPU_ROOT=../gpu ..
make -j$(sysctl -n hw.ncpu)

# CPU only
cmake -DWITH_METAL=OFF ..
make -j$(sysctl -n hw.ncpu)
```

## Dependencies

| Dependency | Required | Purpose |
|------------|----------|---------|
| `kinet-labs/lattice` | Required | NTT operations for ML-DSA |
| `kinet-labs/gpu` | Optional | MLX backend |
| Metal framework | macOS | BLS12-381 compute shaders |
| Foundation/Security | macOS | Apple frameworks |

## Downstream Dependencies

| Package | Uses For |
|---------|----------|
| `kinet/crypto` | Via CGO bridge |
| `kinet/threshold` | BLS threshold signatures |

## Key Files

| File | Purpose |
|------|---------|
| `src/metal/bls12_381.metal` | Metal compute shaders for G1 arithmetic |
| `src/metal_bls.mm` | Metal API wrapper (Objective-C++) |
| `include/metal_bls.h` | Metal BLS C interface |
| `src/crypto.cpp` | Main implementation with GPU dispatch |
| `include/crypto.h` | Public C API |

## Rules for AI Assistants

1. **ALWAYS** use `-DWITH_METAL=ON` on macOS for GPU acceleration
2. Build `kinet-labs/lattice` first (required for ML-DSA)
3. Build `kinet-labs/gpu` first if enabling WITH_GPU
4. Test BLS batch operations with >= 8 signatures to trigger GPU path
5. Metal shaders compile to `.metallib` at build time

---

*This file is symlinked as AGENTS.md, CLAUDE.md*

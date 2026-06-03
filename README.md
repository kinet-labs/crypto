# crypto

cryptography library - BLS12-381 pairings, ML-DSA, ML-KEM post-quantum signatures

## Features

- **BLS12-381** - Pairing-friendly curves for threshold signatures
- **ML-DSA** - Post-quantum digital signatures (CRYSTALS-Dilithium)
- **ML-KEM** - Post-quantum key encapsulation (CRYSTALS-Kyber)
- **secp256k1** - Ethereum-compatible ECDSA

## Installation

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix /usr/local
```

## Usage

### CMake

```cmake
find_package(kinet-crypto REQUIRED)
target_link_libraries(myapp PRIVATE kinet::crypto)
```

### pkg-config (for CGO)

```bash
export CGO_CFLAGS=$(pkg-config --cflags kinet-crypto)
export CGO_LDFLAGS=$(pkg-config --libs kinet-crypto)
```
# crypto

cryptography library - BLS12-381 pairings, ML-DSA, ML-KEM post-quantum signatures


Canonical native cryptographic primitives for the Kinet / Hanzo / Zoo
ecosystem. CPU + GPU implementations live here and only here.

* CPU: portable C++17 / C++20, no third-party crypto libraries
* GPU: CUDA, Metal, WGSL kernels with byte-equal CPU↔GPU output
* C ABI: `include/kinet/crypto/<alg>.h`, callable from Go (cgo) and
  Rust (bindgen / kinet-crypto-sys)

The Go entry point is `github.com/kinet-labs/crypto`; the GPU device router
is `github.com/kinet-labs/go-accel`.

## Status

Phase 1 (current): `secp256k1`, `keccak`. See [`MIGRATION.md`](MIGRATION.md)
for the full per-algorithm migration plan and status.

## Building

```bash
mkdir -p build && cd build
cmake -DKINET_CRYPTO_ENABLE_METAL=ON ..
cmake --build . -j$(nproc)
ctest --output-on-failure
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
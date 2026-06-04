# gpukit

Common GPU kernel-pattern library. Every primitive follows the
`expand_inputs / parallel_eval / reduce / commit_root` shape so that proof
systems (Quasar, BLS, lattice/FHE) consume them uniformly via the
`gpukit_proof_result` artifact.

Brand-neutral: env vars start with `GPUKIT_`, C symbols start with `gpukit_`.
The `kinet/` path scope (`<kinet/gpukit/...>`) is the only place the brand appears.

## Primitives (v1.1)

| Primitive | CPU | Metal | CUDA | WGSL |
|-----------|-----|-------|------|------|
| `prefix_sum`       (u32, u64)            | yes | yes | NOTIMPL on Apple host (built on Linux+CUDA) | NOTIMPL (host integration v1.2) |
| `compaction`       (u32)                 | yes | yes | NOTIMPL on Apple host                         | NOTIMPL |
| `radix_sort`       (u32, u64)            | yes | yes | NOTIMPL on Apple host                         | NOTIMPL |
| `batch_inversion`  (secp256k1, BN254, BLS12-381) | yes | NOTIMPL (BLS Stage 3+) | NOTIMPL | NOTIMPL |
| `merkle_compose`   (Keccak-256)          | yes | NOTIMPL (keccak Stage 2 GPU port) | NOTIMPL | NOTIMPL |
| `transcript_root`  (Keccak sponge)       | yes | NOTIMPL (v1.2 batched) | NOTIMPL | NOTIMPL |
| `ntt`              (Kyber q=3329, Dilithium q=8380417) | yes | NOTIMPL (v1.2) | NOTIMPL | NOTIMPL |

`NOTIMPL` returns `GPUKIT_ERR_NOTIMPL` (-5). The determinism harness
treats NOTIMPL as a *skip* (counted, not failed). Where a backend implements
the primitive, the harness asserts byte-equality vs the CPU reference.

## Build

```sh
cd /Users/z/work/kinet-labs/crypto
cmake -S . -B build-gpukit -DCMAKE_BUILD_TYPE=Release \
  -DKINET_CRYPTO_ENABLE_METAL=ON -DKINET_CRYPTO_ENABLE_WGSL=ON
cmake --build build-gpukit --target gpukit-tests
ctest --test-dir build-gpukit -R "gpukit-" --output-on-failure
```

## Backend selection

```sh
GPUKIT_BACKEND=cpu    # default
GPUKIT_BACKEND=metal  # Apple Metal
GPUKIT_BACKEND=cuda   # NVIDIA CUDA (Linux)
GPUKIT_BACKEND=wgsl   # Dawn / wgpu-native
```

`gpukit_active_backend()` reads this env var. The C ABI per primitive accepts
the backend choice via the `_<backend>` suffix on each function name.

## Layout

```
gpukit/
  CMakeLists.txt
  README.md
  include/kinet/gpukit/             public C ABI
  cpp/cpu_reference/              CPU references (byte-equal target)
  gpu/metal/                      Metal kernels + drivers (.metal + .mm)
  gpu/cuda/                       CUDA kernels (.cu)
  gpu/wgsl/                       WGSL shaders + drivers (.wgsl + .cpp)
  test/                           determinism harness per primitive
```

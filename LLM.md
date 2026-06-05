# kinet-labs/crypto - canonical native + GPU crypto

**Last Updated**: 2026-04-26
**Module**: `kinet-labs/crypto`
**Role**: First-party CPU + GPU cryptographic primitives. Single source of
truth for every algorithm consumed by Go (kinet-labs/crypto), Rust, C++, and
Metal/CUDA/WGSL.

## Layout

One directory per algorithm, identical shape:

```
kinet-labs/crypto/
  c-abi/
    kinet_crypto.h            public umbrella header (Go cgo + Rust bindgen)
    c_kinet_crypto.cpp        top-level dispatcher (GPU control + version)
  include/kinet/crypto/
    keccak.h                first-party per-algorithm public headers
    secp256k1.h
    u256.h
  cmake/
    KinetAlgorithm.cmake      kinet_add_algorithm() helper
  <alg>/
    CMakeLists.txt          uses kinet_add_algorithm(NAME ...)
    cpp/                    first-party CPU implementation
    gpu/cuda/               *.cu kernels (Phase 3+ for most algorithms)
    gpu/metal/              *.metal kernels + *_driver.{h,mm}
    gpu/wgsl/               *.wgsl kernels (Phase 3+)
    c-abi/c_<alg>.{h,cpp}   algorithm-internal C ABI shim (extern "C")
    test/<alg>_test.cpp
    test/<alg>_gpu_test.cpp
    test/<alg>_determinism_test.cpp
    test/vectors/
```

## Algorithms (28)

| # | Name | CPU body | Metal driver | C-ABI shim |
|---|------|----------|--------------|------------|
| 1 | aead | placeholder | -- | stub |
| 2 | blake2b | full (RFC 7693, on cevm compress) | -- | live |
| 3 | blake3 | placeholder | live | stub |
| 4 | bls | placeholder (cevm body needs intx+blst) | live | stub |
| 5 | bn254 | placeholder (cevm body needs intx) | live | stub |
| 6 | cggmp21 | placeholder | -- | stub |
| 7 | ed25519 | placeholder | -- | stub |
| 8 | evm256 | placeholder | -- | stub |
| 9 | frost | placeholder | -- | stub |
| 10 | ipa | placeholder | live | stub |
| 11 | **keccak** | **first-party** | -- | live (batch) |
| 12 | kzg | placeholder (cevm body needs blst) | -- | stub |
| 13 | lamport | placeholder | live | stub |
| 14 | mldsa | placeholder | live | stub |
| 15 | mlkem | placeholder | live | stub |
| 16 | modexp | placeholder (cevm body needs intx) | -- | stub |
| 17 | ntt | placeholder | -- | stub |
| 18 | pedersen | placeholder | -- | stub |
| 19 | poly_mul | placeholder | -- | stub |
| 20 | poseidon | placeholder | live | stub |
| 21 | ringtail | placeholder | -- | stub |
| 22 | ripemd160 | full (cevm body, namespaceable) | -- | live |
| 23 | **secp256k1** | **first-party (ecrecover)** | live (placeholder) | live (recover wrapper) |
| 24 | secp256r1 | placeholder (cevm body needs intx) | -- | stub |
| 25 | sha256 | full (cevm body, namespaceable) | -- | live |
| 26 | slhdsa | placeholder | live | stub |
| 27 | sr25519 | placeholder | -- | stub |
| 28 | verkle | placeholder | -- | stub |

"first-party" = algorithm body authored under kinet-labs/crypto with no third-party
crypto library. "cevm body" = source file relocated from
`kinet-labs/cevm/lib/cevm_precompiles/`; those compile against `intx` and
sometimes `blst`. Phase 3 ports them to first-party.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

CMake options:
- `KINET_CRYPTO_ENABLE_CUDA=ON` (default OFF)
- `KINET_CRYPTO_ENABLE_METAL=ON` (forced ON on Apple)
- `KINET_CRYPTO_ENABLE_WGSL=ON` (default OFF; drivers ship Phase 3+)
- `KINET_CRYPTO_BUILD_TESTS=ON` (default ON)

## Public ABI

`#include <kinet_crypto.h>` -- one header, every symbol:

- Hashes: `kinet_keccak256`, `kinet_sha256`, `kinet_blake2b`, `kinet_blake3`, `kinet_ripemd160`
- AEAD: `kinet_aead_chacha20poly1305_*`
- EC: `kinet_secp256k1_*`, `kinet_secp256r1_*`, `kinet_ed25519_*`, `kinet_sr25519_*`
- Pairings: `kinet_bn254_*`, `kinet_bls_*`
- KZG: `kinet_kzg_*`
- PQ: `kinet_mldsa_*`, `kinet_mlkem_*`, `kinet_slhdsa_*`
- Threshold: `kinet_frost_*`, `kinet_cggmp21_*`, `kinet_ringtail_*`
- ZK: `kinet_ipa_*`, `kinet_lamport_*`, `kinet_pedersen_*`, `kinet_poseidon_*`, `kinet_verkle_*`
- Bigint: `kinet_modexp`, `kinet_evm256_*`
- NTT: `kinet_ntt_*`, `kinet_poly_mul`
- Control: `kinet_crypto_gpu_{available,set_default,get_default}`, `kinet_crypto_version`

## Phase plan

- Phase 1 (this commit): canonical layout + 28 algorithm directories + unified
  C ABI header + per-algorithm CMakeLists.txt + first-party keccak and
  secp256k1 tests passing.
- Phase 3: port the cevm bodies (intx + blst dependencies) to first-party
  implementations under each `<alg>/cpp/`. Implement non-stub C-ABI shims for
  every placeholder.
- Phase 4: rewire downstream consumers (kinet-labs/crypto cgo, hanzo/node, zoo/node,
  kinet/node) to consume the unified `kinet_crypto.h` surface.
- Phase 5: delete `kinet-labs/cevm/lib/cevm_precompiles/` and `kinet-labs/gpu/kernels/`
  after every consumer is on the new path.

## Rules

1. No vendoring. No third-party crypto library. Every byte is authored here.
2. GPU output must be byte-equal to CPU output. Determinism tests prove it.
3. Stub C-ABI shims return `KINET_ERR_NOTIMPL`. They are not exercised by tests.
4. One way to do everything: a caller never has to choose between two
   identical-looking entry points.
5. Originals at `kinet-labs/cevm/lib/cevm_precompiles/` and `kinet-labs/gpu/kernels/`
   stay until Phase 5 sweeps them.

---

*Symlinked as AGENTS.md, CLAUDE.md.*

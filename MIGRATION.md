# kinetcpp/crypto Migration Plan

This file is the canonical record of the per-algorithm migration from the
ecosystem's parallel crypto trees into the single kinetcpp/crypto repository.

## Layout

Every algorithm follows the same structure:

```
kinetcpp/crypto/<alg>/
├── CMakeLists.txt              uses kinet_add_algorithm() helper
├── cpp/                         first-party CPU implementation
│   └── *.{cpp,hpp,h}
├── gpu/
│   ├── cuda/                    *.cu kernels + driver_cuda.cpp
│   ├── metal/                   *.metal kernels + driver_metal.mm
│   └── wgsl/                    *.wgsl kernels + driver_wgpu.cpp
├── c-abi/                       extern "C" shim for Go cgo + Rust bindgen
│   └── c_<alg>.cpp
└── test/
    ├── <alg>_test.cpp           CPU correctness vs RFC/NIST/IEEE vectors
    └── <alg>_gpu_test.cpp       CPU vs GPU byte-equality
```

Public C ABI for every algorithm: `include/kinet/crypto/<alg>.h`.

## Hard rules

1. **No vendoring**. Every implementation under `cpp/` is first-party. If the
   sprawl source tree depends on `blst`, `libsecp256k1`, `gnark-crypto`,
   `circl`, `openssl`, `libsodium`, etc., that dependency is replaced with a
   from-scratch implementation before the algorithm enters this tree.
2. **No stubs**. An algorithm is "done" only when its test harness passes
   byte-equality against the canonical reference vectors (RFC, NIST KAT,
   IEEE S&P, IETF draft, etc.) AND the GPU path is byte-equal to the CPU path
   for the same vectors.
3. **One source of truth**. Once an algorithm lands here, all other
   ecosystem repos delete their copy and route through `kinetcpp/crypto` via
   the C ABI (Go cgo, Rust FFI, C++ direct).

## Status table (29 algorithms)

| Algorithm   | Sprawl source(s)                                                        | Status  | Owner agent  | Test vectors                   |
|-------------|-------------------------------------------------------------------------|---------|--------------|--------------------------------|
| secp256k1   | kinetcpp/cevm/.../secp256k1.cpp, kinetcpp/gpu/kernels/secp256k1_recover.*   | DONE    | phase1       | RFC 6979 §A.2.5 + 64 RT + edge |
| keccak      | kinetcpp/cevm/.../keccak.c (Apache, third-party — replaced)               | DONE    | phase1       | "" / "abc" / 56-byte canon     |
| sha256      | kinetcpp/cevm/.../sha256.cpp                                              | pending | next         | NIST FIPS 180-4                |
| blake2b     | kinetcpp/cevm/.../blake2b.cpp, kinet/crypto/blake2b/                         | pending | next         | RFC 7693                       |
| blake3      | kinetcpp/gpu/kernels/blake3.{cu,metal,wgsl}                               | pending | next         | BLAKE3 reference               |
| ripemd160   | kinetcpp/cevm/.../ripemd160.cpp                                           | pending | next         | RIPEMD-160 spec                |
| modexp     | kinetcpp/cevm/.../modexp.cpp                                               | pending | next         | EIP-198                        |
| bn254       | kinetcpp/cevm/.../bn254.{cpp,hpp}, kinetcpp/cevm/.../pairing/                | pending | next         | EIP-196 / EIP-197              |
| bls12381    | kinetcpp/cevm/.../bls.{cpp,hpp}, kinetcpp/gpu/kernels/bls12_381.*           | pending | bls-agent    | RFC 9380 + IETF BLS Sig draft  |
| kzg         | kinetcpp/cevm/.../kzg.{cpp,hpp}                                           | pending | bls-agent    | EIP-4844 trusted setup tests   |
| evm256     | kinetcpp/gpu/kernels/evm256.{cu,metal,wgsl}                                | pending | next         | EVM 256-bit ALU                |
| secp256r1   | kinet/crypto/secp256r1/                                                   | pending | next         | RIP-7212 + RFC 6979 P-256      |
| ed25519     | kinetcpp/gpu/kernels/ed25519.{cu,metal,wgsl}                              | pending | next         | RFC 8032                       |
| sr25519     | kinetcpp/gpu/kernels/sr25519.{cu,metal,wgsl}                              | pending | next         | sr25519 IETF spec              |
| mldsa       | kinet/crypto/mldsa/, kinetcpp/crypto/src/metal_mldsa.mm                     | pending | pq-agent     | NIST FIPS 204 KAT              |
| mlkem       | kinet/crypto/mlkem/, kinetcpp/crypto/src/metal_mlkem.mm                     | pending | pq-agent     | NIST FIPS 203 KAT              |
| slhdsa      | kinet/crypto/slhdsa/, kinetcpp/crypto/src/metal_slhdsa.mm                   | pending | pq-agent     | NIST FIPS 205 KAT              |
| ringtail    | kinetcpp/lattice/ + kinetcpp/gpu/kernels/ringtail.*                         | pending | threshold    | IEEE S&P 2025 Ringtail tests   |
| frost       | kinet/crypto/threshold/ + kinetcpp/gpu/kernels/frost.*                      | pending | threshold    | RFC 9591                       |
| cggmp21     | kinet/crypto/cggmp21/ + kinetcpp/gpu/kernels/cggmp21.*                      | pending | threshold    | CGGMP21 reference              |
| ipa         | kinet/crypto/ipa/ + kinetcpp/crypto/src/metal_ipa.mm                        | pending | next         | Bulletproofs IPA spec          |
| lamport     | kinet/crypto/lamport/ + kinetcpp/crypto/src/metal_lamport.mm                | pending | next         | LP-2506                        |
| poseidon    | kinetcpp/crypto/src/metal_poseidon2.mm                                    | pending | zk-agent     | Poseidon2 reference            |
| pedersen    | (new)                                                                    | pending | zk-agent     | Bulletproofs                   |
| ntt         | kinetcpp/lattice/ + kinetcpp/gpu/kernels/ntt*.*                             | pending | fhe-agent    | NTT spec                       |
| poly_mul    | kinetcpp/gpu/kernels/poly_mul.*                                           | pending | fhe-agent    | NTRU / KEM polynomial mul      |
| aead        | (new wrapper for ChaCha20-Poly1305 + AES-GCM)                            | pending | next         | RFC 8439, NIST GCM             |
| verkle      | kinet/crypto/verkle/                                                       | pending | next         | EIP-6800 Verkle tests          |

## Next-agent prompts (Phase 2)

### `bls-agent` — BLS12-381 + KZG
Replace `kinetcpp/cevm/cmake/blst.cmake` with a first-party BLS12-381
implementation under `kinetcpp/crypto/bls12381/` and `kinetcpp/crypto/kzg/`.
Tests: RFC 9380 hash-to-curve, IETF BLS Signature scheme draft, EIP-4844
KZG trusted-setup vectors. After byte-equal proof on CPU + GPU, drop
`blst.cmake` from cevm and switch all callers (consensus/quasar,
bridge/threshold, node/warp) to the canonical path.

### `pq-agent` — ML-DSA, ML-KEM, SLH-DSA
Replace `kinet/crypto/mldsa/`, `kinet/crypto/mlkem/`, `kinet/crypto/slhdsa/`
(all currently route through `circl`) with first-party implementations
under `kinetcpp/crypto/mldsa/`, `kinetcpp/crypto/mlkem/`,
`kinetcpp/crypto/slhdsa/`. Tests: NIST FIPS 203/204/205 KAT vectors. The
existing Metal `metal_mldsa.mm`/`metal_mlkem.mm`/`metal_slhdsa.mm`
drivers move into `<alg>/gpu/metal/`.

### `threshold-agent` — Ringtail, FROST, CGGMP21
Move `kinet/crypto/cggmp21/`, `kinet/crypto/threshold/`, and `kinetcpp/lattice/`
into `kinetcpp/crypto/{ringtail,frost,cggmp21}/`. The existing GPU kernels
under `kinetcpp/gpu/kernels/{ringtail,frost,cggmp21}.*` move into
`<alg>/gpu/{cuda,metal,wgsl}/`. Tests: IEEE S&P 2025 Ringtail vectors,
RFC 9591 FROST vectors, CGGMP21 reference suite.

### `zk-agent` — Poseidon2, Pedersen, IPA
Consolidate `kinetcpp/crypto/src/metal_poseidon2.mm`, `metal_ipa.mm`, and
the bn254 EVM precompiles into `kinetcpp/crypto/{poseidon,pedersen,ipa,bn254}/`.

### `fhe-agent` — NTT, poly_mul, FHE kernels
Move `kinetcpp/lattice/` core + `kinetcpp/gpu/kernels/{ntt,poly_mul,fhe_kernels,
blind_rotate,external_product,bsk_prefetch,four_step_ntt,fused_external_product,
ntt_metal_kernel,ntt_unified_memory,reduce,twiddle_cache}.*` into
`kinetcpp/crypto/{ntt,poly_mul}/`. The CKKS/TFHE GPU paths in `kinetcpp/fhe/`
become `kinetcpp/crypto/fhe/` (separate phase).

### `vendored-blst-removal` (final cevm v0.46 cleanup)
After BLS12-381 byte-equal-tests against blst across all RFC 9380 +
IETF BLS Signature draft vectors, delete `kinetcpp/cevm/cmake/blst.cmake`
and the blst submodule. cevm precompiles re-target to
`#include <kinet/crypto/bls12381.h>`.

## Phase 1 deliverables (this commit)

* Canonical layout established, 28 algorithm directories scaffolded.
* `secp256k1` + `keccak` shipped end-to-end:
  * CPU: `cpp/{ecrecover.cpp,field.hpp,curve.hpp}` + `cpp/keccak.cpp`
  * GPU (Metal): `gpu/metal/secp256k1.metal` + driver
  * Tests:
    * `keccak_test`: 3/3 canonical Ethereum vectors PASS
    * `secp256k1_test`: RFC 6979 §A.2.5 PASS, 64/64 round-trip PASS,
      4/4 edge cases PASS, 16/16 batch PASS
    * `secp256k1_gpu_test`: 32/32 byte-equal CPU vs Metal PASS
* C ABI: `include/kinet/crypto/secp256k1.h`, `include/kinet/crypto/keccak.h`
* Go wire-up: `kinetfi/accel.CryptoSecp256k1Ecrecover` (CGO + tag
  `kinet_crypto_native`) + Go-side test PASS

## Forbidden in this tree

* `#include <gnark/...>`
* `#include <blst/...>`
* `#include <libsecp256k1/...>` (we keep our first-party Montgomery code)
* `#include <openssl/...>`
* `#include <sodium/...>`
* `#include <ethash/keccak.h>` (Pawel Bylica Apache-2.0 — replaced)
* `#include <intx/...>` (we ship our own U256 in `secp256k1/cpp/field.hpp`)
* `#include <evmc/...>` (cevm's address types stay in cevm; this tree
  exposes raw `uint8_t[20]` / `uint8_t[64]` only)

## Build status (Apple M-series host, this commit)

```
$ cmake -S . -B build-canonical && cmake --build build-canonical -j8
[100%] Built target secp256k1_test
[100%] Built target secp256k1_gpu_test
[100%] Built target keccak_test
[100%] Built target crypto

$ ./build-canonical/keccak_test
=== ALL TESTS PASSED (0 failures) ===

$ ./build-canonical/secp256k1_test
=== ALL TESTS PASSED (0 failures) ===

$ KINET_CRYPTO_SECP256K1_METALLIB=$(pwd)/build-canonical/kinet_crypto_secp256k1.metallib \
    ./build-canonical/secp256k1_gpu_test
byte-equal: 32/32
=== ALL TESTS PASSED (0 failures) ===
```

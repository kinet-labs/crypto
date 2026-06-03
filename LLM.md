# kinetcpp/crypto - canonical native + GPU crypto

**Last Updated**: 2026-04-26
**Module**: `kinetcpp/crypto`
**Role**: First-party CPU + GPU cryptographic primitives. Single source of
truth for every algorithm consumed by Go (kinetfi/crypto), Rust, C++, and
Metal/CUDA/WGSL.

## Layout

One directory per algorithm, identical shape:

```
kinetcpp/crypto/
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

## Algorithms (29)

| # | Name | CPU body | Metal driver | C-ABI shim |
|---|------|----------|--------------|------------|
| 1 | aead | placeholder | -- | stub |
| 2 | **attestation** | **first-party** (SEV-SNP, TDX, NRAS, composite) | -- | live |
| 3 | blake2b | full (RFC 7693, on cevm compress) | -- | live |
| 4 | blake3 | placeholder | live | stub |
| 5 | bls | placeholder (cevm body needs intx+blst) | live | stub |
| 6 | bn254 | placeholder (cevm body needs intx) | live | stub |
| 7 | cggmp21 | placeholder | -- | stub |
| 8 | ed25519 | placeholder | -- | stub |
| 9 | evm256 | placeholder | -- | stub |
| 10 | frost | placeholder | -- | stub |
| 11 | ipa | placeholder | live | stub |
| 12 | **keccak** | **first-party** | -- | live (batch) |
| 13 | kzg | placeholder (cevm body needs blst) | -- | stub |
| 14 | lamport | placeholder | live | stub |
| 15 | mldsa | placeholder | live | stub |
| 16 | mlkem | placeholder | live | stub |
| 17 | modexp | placeholder (cevm body needs intx) | -- | stub |
| 18 | ntt | placeholder | -- | stub |
| 19 | pedersen | placeholder | -- | stub |
| 20 | poly_mul | placeholder | -- | stub |
| 21 | poseidon | placeholder | live | stub |
| 22 | ringtail | placeholder | -- | stub |
| 23 | ripemd160 | full (cevm body, namespaceable) | -- | live |
| 24 | **secp256k1** | **first-party (ecrecover)** | live (placeholder) | live (recover wrapper) |
| 25 | secp256r1 | placeholder (cevm body needs intx) | -- | stub |
| 26 | sha256 | full (cevm body, namespaceable) | -- | live |
| 27 | slhdsa | placeholder | live | stub |
| 28 | sr25519 | placeholder | -- | stub |
| 29 | verkle | placeholder | -- | stub |

"first-party" = algorithm body authored under kinetcpp/crypto with no third-party
crypto library. "cevm body" = source file relocated from
`kinetcpp/cevm/lib/cevm_precompiles/`; those compile against `intx` and
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

`#include <kinet_crypto.h>` -- one header, every symbol. Brand stays in include
path only; symbols are brand-neutral:

- Hashes: `keccak256`, `sha256`, `blake2b`, `blake3`, `ripemd160`
- AEAD: `aead_chacha20poly1305_*`
- EC: `secp256k1_*`, `secp256r1_*`, `ed25519_*`, `sr25519_*`
- Pairings: `bn254_*`, `bls_*`
- KZG: `kzg_*`
- PQ: `mldsa_*`, `mlkem_*`, `slhdsa_*`
- Threshold: `frost_*`, `cggmp21_*`, `ringtail_*`
- ZK: `ipa_*`, `lamport_*`, `pedersen_*`, `poseidon_*`, `verkle_*`
- Bigint: `modexp`, `evm256_*`
- NTT: `ntt_*`, `poly_mul`
- Control: `crypto_gpu_{available,set_default,get_default}`, `crypto_version`
- Status: `CRYPTO_OK`, `CRYPTO_ERR_*`, `CRYPTO_BACKEND_*`
- Attestation: `attestation_parse_{sev_snp,tdx,nv}`, `attestation_compute_composite_root`, `attestation_verify_baseline`

## Confidential-compute attestation

`<kinet/crypto/attestation/...>` ships software primitives for composite
node attestation:

- `attestation_parse_sev_snp` — parses 1184-byte AMD SEV-SNP report, extracts
  the 48-byte MEASUREMENT field, hashes to 32 bytes via keccak256.
- `attestation_parse_tdx` — parses Intel TDX TD Quote (header + body), extracts
  the 48-byte MRTD, hashes to 32 bytes.
- `attestation_parse_nv` — canonical-hashes the NRAS evidence blob.
- `attestation_compute_composite_root` — keccak256 over the canonical
  serialization of `NodeConfidentialAttestation` (CPU TEE + GPU TEE +
  driver/firmware + quasar binary + crypto kernel + AI model runtime +
  precompile binary + policy root + node identity + epoch + kinds + io_level).
  Goes into `QuasarRoundDescriptor.attestation_root` (cert ABI).
- `attestation_verify_baseline` — per-field expectation check against an
  `AttestationBaseline`. Hash fields zero = wildcard. Kinds NONE = wildcard.

Hardware provisioning (PSP, QGS, NRAS live) is platform-deployment work; the
parsers ship before live hardware is on hand and are exercised against
synthesized fixtures. Real-RIM verification (signed manifest + X.509 chain)
lands when we have a trust anchor on file.

The Go mirror lives at `kinetfi/kms/pkg/attestation`; cross-language parity is
proven by `TestCompositeRoot_MatchesCABI` (canonical root pinned to
`56f1d8e537973913091159c532ecc657f3e0cd63946dfcaea831d42a62682152`).

## v0.63 — 4-kernel pattern applied to crypto

**secp256k1**

- `secp256k1/cpp/batch_inv.hpp` — Montgomery batch inversion for Fp and Fn.
  One Fermat exponentiation + 3(n-1) field multiplications across the batch
  instead of n separate Fermat inversions.
- `secp256k1/cpp/windowed_g_table.hpp` — fixed w=4 windowed G table built once
  at library init. 64 windows × 16 entries = 1024 affine points (~64 KB).
- `secp256k1/cpp/ecrecover_pipeline.hpp` — 7-stage CPU pipeline:
  parse_reject → field_normalize → recover_R → batch_invert(r) →
  scalar_mult(u1·G + u2·R) → batch_invert(Z) → compose_output.
- `secp256k1/gpu/metal/secp256k1_batch_inv.metal` + `_driver.mm` — Metal
  Stage A kernel; CPU↔Metal byte-equal at n ∈ {16, 256, 4096} for both Fp/Fn.
- C ABI: `secp256k1_ecrecover_batch_pipeline()`,
  `secp256k1_ecrecover_address_batch()`.
- Measured speedup at n=1024 CPU: simple loop ~425 ms → pipeline ~232 ms
  (1.80× wall-clock, dominated by the single-Fermat batch inversion).

**keccak**

- `keccak/cpp/keccak_service.hpp` — KeccakJobKind enum (9 kinds) +
  KeccakJob descriptor + per-round dedup cache + in-batch dedup.
- `keccak/gpu/metal/keccak_batch.metal` — one-thread-per-job Keccak-256;
  byte-equal to CPU.
- Mapping-slot dedup hit-rate ≥ 0.50 on synthetic round workload (test shows
  0.67 on 50-unique × 3-call workload).

**Tests added**: `secp256k1_batch_inv_test`, `secp256k1_ecrecover_pipeline_test`,
`secp256k1_batch_inv_gpu_test`, `keccak_service_test`. All pass; combined with
existing `secp256k1_test`, `secp256k1_gpu_test`, `keccak_test` = 7/7.

**Gaps for v0.64**:
- Glv endomorphism for u2·R scalar mult (gated behind a feature flag; must
  preserve byte-equality across CPU/Metal/CUDA/WGSL before enabling).
- Per-stage Metal kernels for the 7 pipeline stages (today's Metal path uses
  the existing single-kernel `secp256k1.metal`; the algorithmic win lives in
  Stage A which already has its own kernel).
- CUDA + WGSL ports of `secp256k1_batch_inv` (Metal only in v0.63).

## Phase plan

- Phase 1 (this commit): canonical layout + 28 algorithm directories + unified
  C ABI header + per-algorithm CMakeLists.txt + first-party keccak and
  secp256k1 tests passing.
- Phase 3: port the cevm bodies (intx + blst dependencies) to first-party
  implementations under each `<alg>/cpp/`. Implement non-stub C-ABI shims for
  every placeholder.
- Phase 4: rewire downstream consumers (kinetfi/crypto cgo, hanzo/node, zoo/node,
  kinet/node) to consume the unified `kinet_crypto.h` surface.
- Phase 5: delete `kinetcpp/cevm/lib/cevm_precompiles/` and `kinetcpp/gpu/kernels/`
  after every consumer is on the new path.

## Rules

1. No vendoring. No third-party crypto library. Every byte is authored here.
2. GPU output must be byte-equal to CPU output. Determinism tests prove it.
3. Stub C-ABI shims return `CRYPTO_ERR_NOTIMPL`. They are not exercised by tests.
4. One way to do everything: a caller never has to choose between two
   identical-looking entry points.
5. Originals at `kinetcpp/cevm/lib/cevm_precompiles/` and `kinetcpp/gpu/kernels/`
   stay until Phase 5 sweeps them.

---

*Symlinked as AGENTS.md, CLAUDE.md.*

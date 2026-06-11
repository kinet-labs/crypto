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
    crypto.h            public umbrella header (Go cgo + Rust bindgen)
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
| 13 | **kzg** | **full (verify_proof: first-party blst pairings; blob ops: vendored kinet-labs/c-kzg-4844 v2.1.7)** | -- | **live (4 ops + batch)** |
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
- `CRYPTO_ENABLE_CUDA=ON` (default OFF)
- `CRYPTO_ENABLE_METAL=ON` (forced ON on Apple)
- `CRYPTO_ENABLE_WGSL=ON` (default OFF; drivers ship Phase 3+)
- `CRYPTO_BUILD_TESTS=ON` (default ON)

## Public ABI

`#include <crypto.h>` -- one header, every symbol. Brand stays in include
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
  `AttestationBaseline`. Each expected field is gated by an explicit
  `require_*` flag: true = strict equality (zero-hash baseline rejected as
  input error), false = field skipped entirely. No implicit wildcards.

Hardware provisioning (PSP, QGS, NRAS live) is platform-deployment work; the
parsers ship before live hardware is on hand and are exercised against
synthesized fixtures. Real-RIM verification (signed manifest + X.509 chain)
lands when we have a trust anchor on file.

The Go mirror lives at `kinet-labs/kms/pkg/attestation`; cross-language parity is
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
- Phase 4: rewire downstream consumers (kinet-labs/crypto cgo, hanzo/node, zoo/node,
  kinet/node) to consume the unified `crypto.h` surface.
- Phase 5: delete `kinet-labs/cevm/lib/cevm_precompiles/` and `kinet-labs/gpu/kernels/`
  after every consumer is on the new path.

## Rules

1. No vendoring. No third-party crypto library. Every byte is authored here.
2. GPU output must be byte-equal to CPU output. Determinism tests prove it.
3. Stub C-ABI shims return `CRYPTO_ERR_NOTIMPL`. They are not exercised by tests.
4. One way to do everything: a caller never has to choose between two
   identical-looking entry points.
5. Originals at `kinet-labs/cevm/lib/cevm_precompiles/` and `kinet-labs/gpu/kernels/`
   stay until Phase 5 sweeps them.

---

## ML-DSA / ML-KEM Metal — honest residual (deps-bootstrap-2026-04-27)

The v0.65 commit (c50bcde6) shipped Metal "skeleton" kernels for mldsa /
mlkem that emitted result code 2 ("deferred") per thread and tests asserted
that. That violated the "100% real impl, 100% test pass" directive — the
test passed on a dispatch-shape oracle, not on cryptographic correctness.

This branch replaces that with honest content:

**What is cryptographically correct, byte-equal NIST FIPS 202 KAT:**
- `mldsa_shake128_jobs` / `mldsa_shake256_jobs` Metal kernels
- `mlkem_shake128_jobs` / `mlkem_shake256_jobs` Metal kernels
- Forward + inverse NTT over q = 8380417 (ML-DSA) — primitive present
- Forward + inverse Kyber NTT over q = 3329 (ML-KEM) — primitive present

**What returns CRYPTO_ERR_NOTIMPL (sentinel byte 0xFB):**
- `mldsa_batch_verify` Metal orchestrator
- `mlkem_batch_decapsulate` Metal orchestrator (also zeroes shared_secret)
- All `mldsa_*` / `mlkem_*` symbols in c-abi/

**What is needed to land full FIPS-204 verify byte-equal NIST KAT:**
- Wire SHAKE128 ExpandA into NTT loop (parse 24-byte chunks → coefficients)
- Wire SHAKE256 ExpandMask + ExpandS for sample bounded
- Implement SampleInBall (challenge polynomial from c̃)
- ByteEncode/Decode for hint h, polynomial z (varying bit lengths)
- HighBits / Decompose / UseHint (FIPS-204 §A.2)
- Range checks `‖z‖∞ < γ₁−β`, `‖h‖₁ ≤ ω`
- Final challenge re-computation + constant-time compare

**What is needed for full FIPS-203 decap:**
- ByteDecode_d_v of c1, decompress to u, NTT(u), s_hat^T · NTT(u), INTT
- Compute m' = v − s^T·u, compress to bits
- SHA3-512 (G) of m'‖h_pk → (K', r')
- K-PKE.Encrypt(ek, m', r') = c'
- Constant-time c == c' compare; final K = K' on match else SHAKE256(z‖c)

Both ports are realistically multi-day. The SHAKE primitives + NTT building
blocks land here so the future verify/decap port composes them without
revisiting hash core.

**Threshold gate routing**: until full verify lands, downstream callers
(kinet-labs/crypto Go bridge) MUST honour `CRYPTO_ERR_NOTIMPL = -5` and route
to the cloudflare/circl CPU implementation. The kernel is NOT a fallback
oracle — it is honestly unimplemented for the verify endpoint.

---

## KZG (EIP-4844) — full coverage of all four ops

The EIP-4844 surface ships four C-ABI symbols:

* `kzg_verify_proof` — point-evaluation precompile (EVM 0x0a). First-party
  body at `cpp/kzg.cpp` using BLS12-381 pairings with a hard-coded `[s]_2`
  G2 setup point. No 4096-element trusted setup needed.
* `kzg_blob_to_commit` — block-builder: blob -> 48-byte commitment.
* `kzg_commit_to_proof` — opens a blob at scalar `z`, returns (proof, y).
* `kzg_verify_blob` — verify (blob, commitment, proof) tuple.

The latter three (EL-side block-builder ops) are backed by vendored
**kinet-labs/c-kzg-4844 v2.1.7** (Apache-2 fork mirroring upstream
ethereum/c-kzg-4844 1:1) pulled via FetchContent. The mainnet 4096-element
trusted setup is embedded at configure time from
`${kinet-labs_c_kzg_4844_SOURCE_DIR}/src/trusted_setup.txt` and loaded once on
first use via `fmemopen` + `load_trusted_setup_file`.

### LP-137 invariant (no blst in production)

c-kzg-4844 transitively references blst. The C-ABI is split into two TUs:

* `c-abi/c_kzg.cpp` — only `kzg_verify_proof`. Pulls `cpp/kzg.cpp`. Defines
  one symbol. cevm's canonical adapter `cevm_bls_kzg_canonical_cpu` compiles
  this TU.
* `c-abi/c_kzg_blob.cpp` — three EL-side ops. Pulls `cpp/kzg_blob.cpp`,
  ckzg_lib, and (transitively) blst. cevm does NOT compile this TU.

The split keeps cevm's call graph blst-free: linker pulls only
`c_kzg.cpp.o` into libevm, `c_kzg_blob.cpp.o` stays unreferenced, ckzg+blst
stay out. Verified by `cevm/test/unittests/no_blst_in_production_test.sh`
which asserts zero `_blst_*` symbols across all 7 production binaries.

### KAT coverage

`kzg/test/kzg_eip4844_test.cpp` runs the full
`${kinet-labs_c_kzg_4844_SOURCE_DIR}/tests/<op>/kzg-mainnet/` consensus-spec KAT
tree against all six ops (the four C-ABI symbols plus
`compute_blob_kzg_proof` and `verify_blob_kzg_proof_batch` exposed via the
first-party C++ surface). 253 cases total, all PASS byte-equal (or
ABI-contract-asserted for malformed inputs):

* `blob_to_kzg_commitment`: 11 cases
* `compute_kzg_proof`: 52 cases
* `compute_blob_kzg_proof`: 15 cases
* `verify_kzg_proof`: 122 cases
* `verify_blob_kzg_proof`: 29 cases
* `verify_blob_kzg_proof_batch`: 24 cases

---

*Symlinked as AGENTS.md, CLAUDE.md.*

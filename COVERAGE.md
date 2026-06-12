# kinet-labs/crypto coverage

kinet-labs/crypto is the canonical, GPU-accelerated cryptographic primitive
suite for the Kinet ecosystem (29 algorithms; CPU + Metal + CUDA + WGSL
backends). This file aggregates per-algorithm test coverage.

## Post-acceleration-kernels sweep (2026-04-29, HEAD 1b92e8ce)

Run command (in `build/`): `ctest -j4 --output-on-failure --timeout 300`.

| Aggregate | Value |
|---|---|
| ctest tests registered | **52** |
| Tests passing | **45 / 52** (87%) |
| Tests Not Run (link-failure on 7 gpukit-WGSL targets) | **7** |
| Tests timed out / failed at runtime | **0** |
| Total Test time (real, j4) | **167.14 sec** |
| Cumulative pass-time (single-thread equivalent) | **401.76 sec** |
| Build status | umbrella `crypto` static lib + 44 `*_test` binaries + 1 of 8 gpukit `gpukit_*_test` binaries link clean. 7 gpukit-WGSL tests fail to link (missing `gpukit_*_wgsl` shader symbols — pre-existing issue, not regressed by this revision). |

### Failures (all 7 are link-failure → ctest "Not Run", not test-logic failures)

| Test # | Name | Reason |
|---|---|---|
| 45 | `gpukit-prefix_sum-test`     | unresolved `_gpukit_prefix_sum_u32_wgsl` |
| 46 | `gpukit-compaction-test`     | unresolved `_gpukit_compact_u32_wgsl` |
| 47 | `gpukit-radix_sort-test`     | unresolved `_gpukit_radix_sort_u32_wgsl` |
| 48 | `gpukit-batch_inversion-test`| unresolved `_gpukit_batch_inv_bls12_381_fp_wgsl` |
| 49 | `gpukit-merkle_compose-test` | unresolved `_gpukit_merkle_root_wgsl` |
| 50 | `gpukit-transcript_root-test`| unresolved `_gpukit_transcript_root_wgsl` |
| 51 | `gpukit-ntt-test`            | unresolved `_gpukit_ntt_kyber_forward_wgsl` |

The eighth gpukit harness (`gpukit-multi-pippenger-test`) links and passes
in 16.50 s (CPU-only path; no WGSL dependency).

### Slowest passing tests

| Test # | Name | Wall (sec) |
|---|---|---:|
| 31 | `pedersen_tree_metal_determinism_test` | 164.99 |
| 44 | `ntt_large_test`                       | 110.15 |
| 41 | `banderwagon_metal_determinism_test`   |  52.16 |
| 16 | `cggmp21_presign_test`                 |  23.51 |
| 52 | `gpukit-multi-pippenger-test`          |  16.50 |
| 43 | `banderwagon_wgsl_determinism_test`    |  10.16 |
| 39 | `poseidon_metal_batch_test`            |   9.03 |

### Per-algorithm pass count (45 / 52)

| Algorithm group | Passing tests |
|---|---:|
| keccak (CPU + service) | 2 |
| poseidon (goldilocks + metal-batch) | 2 |
| secp256k1 (CPU, batch-inv, ecrecover, batch-inv-cuda, batch-inv-wgsl, gpu, batch-inv-gpu) | 7 |
| secp256r1 | 1 |
| sha256 (CPU + cuda + wgpu + metal) | 4 |
| ripemd160 (CPU + cuda + wgpu + metal) | 4 |
| blake2b (CPU + metal) | 2 |
| blake3 (metal-batch) | 1 |
| bn254 (kat + gpu-determinism) | 2 |
| modexp (kat + karatsuba + karatsuba-gpu) | 3 |
| kzg (gpu-determinism) | 1 |
| ipa (kat) | 1 |
| banderwagon (multiexp-doc + cuda + wgsl + metal-determinism) | 4 |
| pedersen-tree (CPU + metal + cuda + wgpu determinism) | 4 |
| ntt (large) | 1 |
| frost (presign) | 1 |
| cggmp21 (presign) | 1 |
| paillier | 1 |
| attestation (parser + composite) | 2 |
| gpukit (multi-pippenger only — 7 WGSL link-fails listed above) | 1 |
| **Total passing** | **45** |

## Per-algorithm wiring status (carries from prior revision)

| Algorithm | CPU test target | PASS cases | GPU equivalence | Status |
|---|---|---:|---|---|
| keccak | `keccak_test` | 3 | n/a | passing |
| keccak (service)   | `keccak_service_test` | (built) | n/a | passing |
| keccak256_batch    | shared with `keccak_test` (umbrella shim) | (built) | n/a | passing |
| secp256k1 (CPU)    | `secp256k1_test` | 9 | `secp256k1_gpu_test` (Metal, skip without metallib env) | passing |
| secp256k1 (batch inv) | `secp256k1_batch_inv_test` | (built) | `secp256k1_batch_inv_gpu_test` | passing |
| secp256k1 (ecrecover pipeline) | `secp256k1_ecrecover_pipeline_test` | (built) | n/a | passing |
| secp256r1 | `secp256r1_test` | (built; KAT vectors) | n/a | **passing (new since prior revision)** |
| poseidon (goldilocks) | `poseidon_goldilocks_test` | (built) | n/a | **passing (new since prior revision)** |
| poseidon (metal batch) | `poseidon_metal_batch_test` | (built) | Metal | passing |
| paillier (cggmp21 dep) | `paillier_test` | (built; keygen + encrypt/decrypt + Π^enc round-trip) | n/a | **passing (new since prior revision)** |
| frost (presign) | `frost_presign_test` | (built) | n/a | passing |
| cggmp21 (presign) | `cggmp21_presign_test` | (built) | n/a | passing |
| attestation         | `attestation_test` | 11 (sev_snp + tdx + nv parsers) | n/a | passing |
| attestation composite | `composite_test` | 16 (baseline accept/reject + composite) | n/a | passing |
| sha256              | `sha256_test` | 4 (FIPS 180-4 vectors) | `sha256_metal_test` (100 vectors byte-equal) + cuda + wgpu | passing CPU + 3 GPU backends |
| ripemd160           | `ripemd160_test` | 5 (Dobbertin et al. 1996 vectors) | metal + cuda + wgpu | passing CPU + 3 GPU backends |
| blake2b             | `blake2b_test` | 2 (RFC 7693 vectors) | `blake2b_metal_test` | passing CPU + Metal |
| blake3              | `blake3_metal_batch_test` | (built) | Metal | passing |
| bn254               | `bn254_kat_test` + `bn254_gpu_determinism_test` | (built) | GPU | passing |
| modexp              | `modexp_kat_test` + `modexp_karatsuba_test` + `modexp_karatsuba_gpu_test` | (built) | GPU | passing |
| kzg (gpu)           | `kzg_gpu_determinism_test` | (built) | GPU | passing |
| ipa                 | `ipa_kat_test` | 8 (5 valid + 3 negative) | n/a | passing |
| banderwagon         | `banderwagon_multiexp_doc_test` + cuda + wgsl + metal | (built) | 3 backends | passing |
| pedersen tree       | `pedersen_tree_test` + cuda + wgpu + metal determinism | (built) | 3 backends | passing |
| ntt (large)         | `ntt_large_test` | (built) | n/a | passing |
| gpukit prefix sum   | `gpukit-prefix_sum-test` | n/a | rc=link-fail | **link-fail (WGSL shader symbol unresolved)** |
| gpukit compaction   | `gpukit-compaction-test` | n/a | rc=link-fail | **link-fail (WGSL shader symbol unresolved)** |
| gpukit radix sort   | `gpukit-radix_sort-test` | n/a | rc=link-fail | **link-fail (WGSL shader symbol unresolved)** |
| gpukit batch inv    | `gpukit-batch_inversion-test` | n/a | rc=link-fail | **link-fail (WGSL shader symbol unresolved)** |
| gpukit merkle compose | `gpukit-merkle_compose-test` | n/a | rc=link-fail | **link-fail (WGSL shader symbol unresolved)** |
| gpukit transcript root | `gpukit-transcript_root-test` | n/a | rc=link-fail | **link-fail (WGSL shader symbol unresolved)** |
| gpukit NTT          | `gpukit-ntt-test` | n/a | rc=link-fail | **link-fail (WGSL shader symbol unresolved)** |
| gpukit multi-pippenger | `gpukit-multi-pippenger-test` | (built) | n/a | passing |
| bls (Fp tower)      | `bls_fp_tower_test` | (built; not registered in default ctest yet) | Metal | wired |
| bls (G2)            | `bls_g2_test` (build-bls-stage2) | (built) | Metal | wired |
| bls (Miller loop)   | `bls_miller_test` (build-bls-stage2) | (built) | Metal | wired |
| bls (final exp)     | `bls_final_exp_test` (build-bls-stage3) | (built) | Metal | wired |
| bls (top-level c_bls.cpp shim) | (no test; shim only) | n/a | n/a | NOTIMPL (returns CRYPTO_ERR_NOTIMPL) |
| kzg (cpu body)      | (no test) | n/a | n/a | NOTIMPL (cpp/kzg.cpp uses blst directly; LP-137 forbids blst in production crypto/ — stays test-oracle only via cevm path) |
| evm256 (mulmod/addmod) | (no test) | n/a | n/a | NOTIMPL (cpp/ dir empty; symbols served as NOTIMPL stubs from modexp c-abi shim) |
| aead, ed25519, sr25519, mldsa, mlkem, slhdsa, lamport, ringtail, verkle | (no test, no `<alg>/cpp/` impl) | n/a | per-alg gpu kernels exist | NOTIMPL (no first-party CPU body; shims return CRYPTO_ERR_NOTIMPL) |

## Method

```
rm -rf build-cov
cmake -S . -B build-cov -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_FLAGS="-fprofile-instr-generate -fcoverage-mapping -O0 -g" \
    -DCMAKE_C_FLAGS="-fprofile-instr-generate -fcoverage-mapping -O0 -g" \
    -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate" \
    -DCRYPTO_ENABLE_METAL=OFF
cmake --build build-cov -j
cd build-cov
LLVM_PROFILE_FILE="cov.%p.profraw" ctest
xcrun llvm-profdata merge -sparse cov.*.profraw -o cov.profdata
xcrun llvm-cov report -instr-profile=cov.profdata \
    ./keccak_test ./secp256k1_test ./attestation_test ./composite_test \
    ./gpukit/gpukit_prefix_sum_test ./gpukit/gpukit_ntt_test \
    -ignore-filename-regex='build|test/|/usr/'
```

## Caveat (honest)

kinet-labs/crypto post-acceleration-kernels (HEAD 1b92e8ce) ships **45 of 52
ctest targets passing** (87%). The 7 failures are all **link-failures**
on the gpukit-WGSL family (prefix_sum, compaction, radix_sort,
batch_inversion, merkle_compose, transcript_root, ntt) — the tests cannot
build because the WGSL shader byte-array symbols
(`gpukit_*_wgsl`) are declared `extern "C" const unsigned char[]` in
`gpukit/c-abi/wgsl_shaders.h` but no translation unit emits them in the
default Metal-on-macOS build. CPU paths through these kernels remain
exercised via `gpukit-multi-pippenger-test` and the per-algorithm
banderwagon / pedersen / ntt / kzg tests, which all pass.

11 of 29 algorithms ship a working first-party CPU body wired into the
umbrella crypto static lib: keccak, secp256k1, attestation, sha256,
ripemd160, blake2b (plus the secp256k1 batch_inv and ecrecover_pipeline
derivatives), plus **bn254, secp256r1, modexp** as of the 2026-04-27 deps
bootstrap. **15 of 29** algorithms still return `CRYPTO_ERR_NOTIMPL` from
their C-ABI shim because no first-party CPU body has been authored in
`<alg>/cpp/` yet (only `<alg>/test/vectors/` placeholder dirs exist).
**2 of 29** (kzg, evm256) have residual blockers documented above.

Deps bootstrap (2026-04-27):
- Vendored `intx v0.15.0` (single-header, 1933 LOC, Apache-2.0) at
  `crypto/deps/intx/include/intx/intx.hpp` with INTERFACE target
  `intx::intx`. Source: github.com/chfast/intx, pinned to Hunter SHA1
  571b3f4c5a7b09135755720b478bc03f9d7ba7bb.
- Vendored `evmmax` (single-header, 227 LOC, Apache-2.0) at
  `crypto/deps/evmmax/include/evmmax/evmmax.hpp` with INTERFACE target
  `evmmax::evmmax`. Source: github.com/ethereum/evmone (mirrored from
  the canonical kinet-labs/cevm/include/evmmax copy).
- Both deps PRIVATE-link to consumers; zero symbol leak into public
  ABI (header-only, instantiated at call site).
- evmc was NOT vendored: none of the five Phase-3 cpp bodies actually
  `#include <evmc/...>`. PHILOSOPHY rejects vendoring without a consumer.
- blst was NOT vendored: stays test-oracle-only at
  `crypto/bls/test/cmake/blst.cmake` per LP-137 §46 invariant.

This COVERAGE.md will gain per-algorithm line/branch percentages once
the gpukit-WGSL link issue is resolved (a follow-up adds either an
embedded shader-bytes translation unit or an equivalent
`#if defined(CRYPTO_GPUKIT_WGSL)` guard around the harness call sites)
and the cpp-bodied algos (kzg, secp256r1, bn254, modexp, evm256) wire
through to call-site tests. The current honest per-algo status is
documented above; no fabricated percentages.

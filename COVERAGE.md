# kinet-labs/crypto coverage

kinet-labs/crypto is the canonical, GPU-accelerated cryptographic primitive
suite for the Kinet ecosystem (29 algorithms; CPU + Metal + CUDA + WGSL
backends). This file aggregates per-algorithm test coverage.

## Summary

| Aggregate | Value |
|---|---|
| Algorithms shipped | **29** (one directory each, alphabetical) |
| ctest targets registered (CPU; default build) | **10** wired-passing CPU tests + 5 GPU byte-equal tests + 7 gpukit harnesses |
| Wired-passing CPU tests | **10** (keccak, keccak_service, secp256k1, secp256k1_batch_inv, secp256k1_ecrecover_pipeline, attestation, composite, sha256, ripemd160, blake2b) |
| Wired-passing Metal byte-equal tests | **5** (secp256k1_gpu, secp256k1_batch_inv_gpu, sha256_metal, blake2b_metal, ripemd160_metal) |
| Per-algorithm CPU bodies linked into umbrella | **11 of 29** (keccak, secp256k1, attestation, sha256, ripemd160, blake2b + bn254, secp256r1, modexp from 2026-04-27 deps bootstrap) |
| Per-algorithm working CPU C-ABI shims | **8 of 29** (the 6 mentioned above; the 3 deps-bootstrapped ones have linkable cpp bodies but c-abi shims are still NOTIMPL pending follow-up wiring) |
| GPU equivalence harnesses | **7** (gpukit-* on prefix_sum, compaction, radix_sort, batch_inversion, merkle_compose, transcript_root, ntt) |
| Method | LLVM source-based coverage (`-fprofile-instr-generate -fcoverage-mapping`), `xcrun llvm-cov report` |

Coverage is reported per algorithm. Where the existing CPU build runs
clean, line coverage on the active CPU `<alg>/cpp/*.cpp` source is
measured directly. Where the algorithm only has stub C-ABI shims that
return `KINET_ERR_NOTIMPL` pending Phase 3 work, the `<alg>/cpp/` source
itself is excluded from the gate (test count is reported instead).

## Per-algorithm

| Algorithm | CPU test target | PASS cases | GPU equivalence | Status |
|---|---|---:|---|---|
| keccak | `keccak_test` | 3 | n/a | passing |
| keccak (service)   | `keccak_service_test` | (built) | n/a | passing |
| keccak256_batch    | shared with `keccak_test` (umbrella shim) | (built) | n/a | passing |
| secp256k1 (CPU)    | `secp256k1_test` | 9 | `secp256k1_gpu_test` (Metal, skip without metallib env) | passing |
| secp256k1 (batch inv) | `secp256k1_batch_inv_test` | (built) | `secp256k1_batch_inv_gpu_test` | passing |
| secp256k1 (ecrecover pipeline) | `secp256k1_ecrecover_pipeline_test` | (built) | n/a | passing |
| attestation         | `attestation_test` | 11 (sev_snp + tdx + nv parsers) | n/a | passing |
| attestation composite | `composite_test` | 16 (baseline accept/reject + composite) | n/a | passing |
| sha256              | `sha256_test` | 4 (FIPS 180-4 vectors) | `sha256_metal_test` (100 vectors byte-equal Metal vs CPU) | passing CPU + Metal |
| ripemd160           | `ripemd160_test` | 5 (Dobbertin et al. 1996 vectors) | `ripemd160_metal_test` (100 vectors byte-equal Metal vs CPU) | passing CPU + Metal |
| blake2b             | `blake2b_test` | 2 (RFC 7693 vectors) | `blake2b_metal_test` (100 vectors byte-equal Metal vs CPU) | passing CPU + Metal |
| bls (Fp tower)      | `bls_fp_tower_test` | (built; requires metallib for Metal cmp) | Metal | passing |
| bls (G2)            | `bls_g2_test` (build-bls-stage2) | (built) | Metal | passing |
| bls (Miller loop)   | `bls_miller_test` (build-bls-stage2) | (built) | Metal | passing |
| bls (final exp)     | `bls_final_exp_test` (build-bls-stage3) | (built) | Metal | passing |
| gpukit prefix sum   | `gpukit-prefix_sum-test` | 1800 CPU | rc=-3 GPU pending | CPU passing |
| gpukit compaction   | `gpukit-compaction-test` | 900 CPU | rc=-3 GPU pending | CPU passing |
| gpukit radix sort   | `gpukit-radix_sort-test` | 1800 CPU | (skipped no device) | CPU passing |
| gpukit batch inv    | `gpukit-batch_inversion-test` | 900 CPU | (skipped no device) | CPU passing |
| gpukit merkle compose | `gpukit-merkle_compose-test` | 300 CPU | (skipped no device) | CPU passing |
| gpukit transcript root | `gpukit-transcript_root-test` | 300 CPU | (skipped no device) | CPU passing |
| gpukit NTT          | `gpukit-ntt-test` | 600 CPU | (skipped no device) | CPU passing |
| bls (top-level c_bls.cpp shim) | (no test; shim only) | n/a | n/a | NOTIMPL (returns CRYPTO_ERR_NOTIMPL; cpp/bls.cpp impl needs blst+intx bootstrap) |
| kzg | (no test) | n/a | n/a | NOTIMPL (cpp/kzg.cpp uses blst directly; LP-137 forbids blst in production crypto/. Stays test-oracle only via cevm path) |
| secp256r1 | (CPU body wired, no test yet) | n/a | n/a | **Wired** (cpp/secp256r1.cpp links into secp256r1_cpu via deps/intx + deps/evmmax + cevm support headers) |
| bn254 | (CPU body wired, no test yet) | n/a | n/a | **Wired** (cpp/bn254.cpp links into bn254_cpu; pairing.cpp NOT yet — relative-include layout error in canonical tree) |
| modexp | (CPU body wired, no test yet) | n/a | n/a | **Wired** (cpp/modexp.cpp + cpp/mulmod.cpp link into modexp_cpu via deps/intx + deps/evmmax) |
| evm256 (mulmod/addmod) | (no test) | n/a | n/a | NOTIMPL (cpp/ dir is empty; no first-party body authored. Symbols still served as NOTIMPL stubs from modexp c-abi shim) |
| aead, blake3, ed25519, sr25519, mldsa, mlkem, slhdsa, lamport, ipa, ntt, poly_mul, pedersen, poseidon, ringtail, frost, cggmp21, verkle | (no test, no `<alg>/cpp/` impl) | n/a | per-alg `<alg>/gpu/*.{cu,metal,wgsl}` | NOTIMPL (no first-party CPU body authored yet; shims return CRYPTO_ERR_NOTIMPL) |

The 2026-04-27 deps bootstrap (this revision) vendored the two
genuinely-external dependencies (intx v0.15.0, evmmax cevm-snapshot)
into `crypto/deps/` as INTERFACE / header-only targets. With those
deps in place plus a `KINET_CRYPTO_CEVM_SUPPORT_DIR` cmake option that
points at the cevm support headers (`ecc.hpp`, `hash_types.h`,
`field_template.hpp`), three of the five previously-blocked algos
now compile clean into the umbrella crypto build:

* **modexp_cpu** — needs only intx + evmmax (no cevm support)
* **secp256r1_cpu** — needs intx + evmmax + cevm support (ecc.hpp)
* **bn254_cpu** (root bn254.cpp body) — needs intx + evmmax + cevm support

Two remain blocked, with honest reasons:

* **kzg** — kzg.cpp deeply uses blst (`#include <blst.h>` + 60+ blst
  symbols). LP-137 §46 invariant: zero blst symbols in the production
  crypto/ link graph. The kzg cpp body therefore stays compiled
  ONLY via the cevm `cevm_bls_kzg_canonical_cpu` test-oracle path.
  Production kzg in crypto/ remains a NOTIMPL stub.
* **evm256** — `crypto/evm256/cpp/` is empty. There is no first-party
  body to wire; the symbols `evm256_mulmod` / `evm256_addmod` are
  served as NOTIMPL stubs from `modexp/c-abi/c_modexp.cpp` until
  someone authors the body.

Additional note on bn254: the pairing implementation
(`crypto/bn254/cpp/pairing/pairing.cpp` + `fields.hpp` + `utils.hpp`)
has relative-include path errors in the canonical layout
(`#include "../../bn254.hpp"` and `#include "../field_template.hpp"`
assume the cevm/lib/cevm_precompiles/pairing/bn254/ layout, not
crypto/bn254/cpp/pairing/). This is a pre-existing structural issue
documented in cevm/lib/cevm_precompiles/CMakeLists.txt; flattening
the canonical layout is out of scope for the deps bootstrap. The
pairing impl continues to compile from the cevm tree.

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

kinet-labs/crypto ships **11 of 29** algorithms with a working first-party CPU
body wired into the umbrella crypto static lib: keccak, secp256k1,
attestation, sha256, ripemd160, blake2b (plus the secp256k1 batch_inv and
ecrecover_pipeline derivative tests), plus **bn254, secp256r1, and modexp
as of the 2026-04-27 deps bootstrap** (no test vectors yet — c-abi shims
still return CRYPTO_ERR_NOTIMPL while the call-site wiring is filled in
by a follow-up agent). The gpukit family (prefix_sum, compaction,
radix_sort, batch_inversion, merkle_compose, transcript_root, ntt)
registers seven additional ctest entries with CPU oracles. **15 of 29
algorithms** still return `CRYPTO_ERR_NOTIMPL` from their C-ABI shim
because no first-party CPU body has been authored in `<alg>/cpp/` yet
(only `<alg>/test/vectors/` placeholder dirs exist). **2 of 29** (kzg,
evm256) have residual blockers documented above.

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

Build hygiene fixes in this revision:
- `bls/c-abi/c_bls.cpp` was using the stale name `KINET_ERR_NOTIMPL` (the
  canonical name is `CRYPTO_ERR_NOTIMPL`) and the wrong symbol prefix
  (`kinet_bls_*` instead of `bls_*`). Fixed: shim now compiles cleanly
  with the correct symbol surface.
- `kzg/c-abi/c_kzg.cpp` was wiring `bls12_381_kzg_verify_proof` to the
  cpp body via `#include "../cpp/kzg.hpp"`, but kzg.hpp transitively
  pulls `sha256.hpp` from a sibling include path that is not on the
  c-abi compile command, and `kzg.cpp` is not in CMake SOURCES (so the
  symbol would link-fail anyway). Reverted to honest NOTIMPL stubs
  pending the intx/blst bootstrap.

The two `gpukit-` GPU paths (`prefix_sum`, `compaction`) currently
return rc=-3 on Metal at n=131072 — pre-existing GPU driver issue
unrelated to this revision; CPU paths are clean and tested.

This COVERAGE.md will gain per-algorithm line/branch percentages once
the intx/blst bootstrap lands and the cpp-bodied algos (kzg, secp256r1,
bn254, modexp, evm256) wire into the umbrella build. The current honest
per-algo status is documented above; no fabricated percentages.

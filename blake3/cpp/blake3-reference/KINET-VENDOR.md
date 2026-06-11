# Vendored: BLAKE3 reference C implementation

- Upstream:  https://github.com/BLAKE3-team/BLAKE3
- Tag:       v1.5.0
- Commit:    5aa53f0 (`version 1.5.0`)
- License:   CC0 1.0 OR Apache-2.0 (dual-licensed; see LICENSE)
- Vendored:  2026-04-27

## What is here

Portable-only subset of `BLAKE3-1.5.0/c/`:

| File                  | LOC  | Origin                     |
|-----------------------|------|----------------------------|
| blake3.h              |   82 | unmodified                 |
| blake3_impl.h         |  285 | unmodified                 |
| blake3.c              |  616 | unmodified                 |
| blake3_dispatch.c     |  305 | unmodified                 |
| blake3_portable.c     |  160 | unmodified                 |
|                       | 1448 |                            |

Total: 1448 lines of portable C.

## What is NOT here

The upstream `c/` tree also ships hand-tuned x86_64 assembly (SSE2/SSE4.1/AVX2/
AVX512) and ARM NEON intrinsics. We deliberately do NOT vendor those: the
portable C path is byte-equal to the SIMD paths (they are all canonical BLAKE3
implementations of the same spec) and avoids ASM toolchain coupling. Callers
needing peak CPU throughput should rely on the GPU drivers (Metal/CUDA) for
batched workloads; SIMD can be re-enabled later as a build option without
breaking ABI.

## How dispatch is configured

`blake3_dispatch.c` reads compile-time defines:

```
BLAKE3_NO_SSE2
BLAKE3_NO_SSE41
BLAKE3_NO_AVX2
BLAKE3_NO_AVX512
BLAKE3_USE_NEON=0
```

When all five are set, dispatch falls through to the portable path
(`blake3_portable.c`) on every call. This is identical to upstream's
`BLAKE3_DISABLE_SIMD()` cmake macro. We set them via `target_compile_definitions`
in the parent `blake3/CMakeLists.txt`.

## Why fork / vendor

Same rationale as PQClean (kinet-labs/crypto/mldsa/cpp/pqclean/, kinet-labs/crypto/
mlkem/cpp/pqclean/, kinet-labs/crypto/slhdsa/cpp/pqclean/):

1. **Reproducibility.** A pinned snapshot of the spec implementation. Future
   audits diff against a known-stable tree, not a moving upstream.
2. **No vendor / supply-chain risk.** Build & test offline; no FetchContent
   surprises mid-CI.
3. **License is permissive.** CC0/Apache-2.0 — vendoring with attribution is
   the canonical pattern.
4. **Byte-equality is the contract.** Pinning fixes the test-vector surface.

## Updating

Bump procedure (only when upstream cuts a new release with security or perf
fixes that matter to us):

1. `git clone --depth 1 --branch <tag> https://github.com/BLAKE3-team/BLAKE3.git /tmp/BLAKE3`
2. `cp /tmp/BLAKE3/c/{blake3.c,blake3.h,blake3_impl.h,blake3_dispatch.c,blake3_portable.c} cpp/blake3-reference/`
3. `cp /tmp/BLAKE3/LICENSE cpp/blake3-reference/LICENSE`
4. `cp /tmp/BLAKE3/test_vectors/test_vectors.json test/vectors/test_vectors.json`
5. Update tag/commit/date at the top of this file.
6. `cd kinet-labs/crypto && cmake -B build-cto -DKINET_CRYPTO_BUILD_TESTS=ON && cmake --build build-cto && ctest -R blake3 --test-dir build-cto`
7. KAT count must be 35 cases x 4 modes = 140 PASS.

No other files in this directory are kinet-labs-authored — every byte under
`cpp/blake3-reference/` (other than this `KINETFI-VENDOR.md`) is an unmodified
copy from BLAKE3-team/BLAKE3.

# BLS12-381 GPU pairing — staged port (no host fallback)

Reference: `cevm/build/_3rdParty/blst-build` (build-time test oracle only — never linked into production library).

Each stage ships verifiable, byte-equal-blst code. No stubs, no TODO in shipped files.

## Stage 1 — Fp2/Fp6/Fp12 arithmetic on Metal ✓ (commit 76a0fa97, tag bls-stage-1)

Tower of extensions over BLS12-381 base field. 1900/1900 byte-equal blst.

- `gpu/metal/bls_fp2.metal` — add/sub/neg/mul(Karatsuba)/sqr/inv/conj/frobenius
- `gpu/metal/bls_fp6.metal` — add/sub/mul/sqr/inv/frobenius
- `gpu/metal/bls_fp12.metal` — add/sub/mul/sqr/inv/conj/frobenius/cyclotomic_sqr
- `test/bls_fp_tower_oracle.cpp` — generates 100 random vectors per op via blst at build time
- `test/bls_fp_tower_test.mm` — runs every vector through Metal, asserts byte-equal blst output

## Stage 2 — G2 affine/Jacobian + Miller loop on Metal (next agent)

Scope: ~500 LOC additional Metal + ~400 LOC test.

- `gpu/metal/bls_g2.metal` — affine + Jacobian add/double/mixed-add, scalar mul (windowed NAF)
- `gpu/metal/bls_miller.metal` — optimal ate Miller loop with x = -0xd201000000010000;
  doubling line + addition line accumulated into Fp12.
- `test/bls_g2_test.mm` — 100 random G2 ops vs blst.
- `test/bls_miller_test.mm` — 100 random (P, Q) pairs vs `blst_miller_loop` post-Miller pre-final-exp output.

Acceptance: byte-equal blst on all G2 ops + all Miller outputs (Fp12, 576 bytes each).

## Stage 3 — Final exponentiation + full pairing on Metal

Scope: ~300 LOC additional Metal + ~400 LOC test.

- `gpu/metal/bls_final_exp.metal` — easy part (1/Fp12 inv via conj when in cyclotomic subgroup) + hard part (cyclotomic-friendly chain using x).
- `gpu/metal/bls_pairing.metal` — public entry: `bls12_381_pairing_batch_verify(...)` using all stages.
- `test/bls_pairing_test.mm` — 8 categories from the brief: e(G1,G2_gen), random pair, bilinearity, aggregate batches (1/16/256/1024/4096), tampered batch, identity, cofactor clearing, subgroup check.

Acceptance: byte-equal blst across all 8 categories.

## Stage 4 — Port Stages 1-3 to CUDA + WGSL

Scope: ~3× Stage 1-3 Metal, mostly translation but each backend has gotchas:
- WGSL: 12×u32 limbs for Fp; vec2<u32> for u64 carry; `rotl64(x, n)` masked.
- CUDA: native uint64_t, inline-PTX for mul.lo/hi where helpful.
- Metal already done.

Acceptance: same vectors run against all 3 backends; all match blst byte-for-byte.

## Stage 5 — Wire-back to consumers

- `cevm/lib/consensus/quasar/gpu/quasar_bls_verifier.cpp` — replace host blst calls with GPU pairing batch entry. blst stays as test oracle.
- `bridgevm/src/bridgevm_bls.cpp` — replace host blst batching with on-device pairing.
- `cevm/cmake/blst.cmake` — drop from production build path (kept only in test target).

Acceptance: cevm 33+13+6+7=59 tests still pass; bridgevm 49/49 still pass; all backends still byte-equal.

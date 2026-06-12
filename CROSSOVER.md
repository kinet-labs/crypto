# Metal CPU/GPU Crossover Thresholds (M1 Max, Release)

Per-primitive crossover sweep — smallest batch size N where median Metal
time <= median CPU time on Apple M1 Max, Release build (`-O3 -DNDEBUG`),
median of >=10 runs.

This file is the canonical per-primitive threshold table for
threshold-gated dispatch. Pattern matches `Threshold*` constants in
`kinet-labs/crypto/gpu/zk.go` and `kQuasarSubstrateMetalThreshold` in
`cevm/lib/consensus/quasar/gpu/quasar_gpu_engine.hpp`.

## Hardware

- CPU: Apple M1 Max (10-core, 8P+2E)
- GPU: Apple M1 Max (32-core integrated, 10.4 TFLOPS FP32)
- RAM: 64 GB unified
- macOS: 26.4 (build 25E241)
- Toolchain: Apple Clang 17
- Date: 2026-04-27

## Per-primitive crossover table

| Primitive | Op | CPU baseline | Metal at headline N | N_threshold | Recommended action |
|-----------|----|-------------|---------------------|-------------|---------------------|
| Keccak-256 | batch hash, 32-byte input | ~225 ns/hash | 0.13 us/hash at N=8192 (1.5x); 0.04 us/hash at N=65536 (3.6x) | **N=6144** (~1.16x) | gate at n>=6144; bypass for state-trie nodes <6k |
| FHE NTT | N=1024 fused | 23.1 us at B=1 | 292.9 us at B=32 (2.31x); 446.1 us at B=128 (6.21x) | **B=32** (per-poly batch) | gate at B>=32 for N=1024 |
| FHE NTT | N=2048 fused | 50.7 us at B=1 | 318.6 us at B=8 (1.17x); 582.9 us at B=128 (10.23x) | **B=8** | gate at B>=8 for N=2048 |
| FHE NTT | N=4096 fused | 101.4 us at B=1 | 438.8 us at B=8 (1.90x); 936.1 us at B=128 (14.02x) | **B=8** | gate at B>=8 for N=4096; **production sweet spot at B=128 (14x)** |
| FHE NTT | N=8192 non-fused | 223.8 us at B=1 | 3473 us at B=32 (2.06x); 4555 us at B=128 (6.28x) | **B=32** | gate at B>=32 for N=8192 |
| FHE NTT | N=16384 non-fused | 480.3 us at B=1 | 3617 us at B=8 (1.07x); 6390 us at B=128 (9.65x) | **B=8** | gate at B>=8 for N=16384 |
| secp256k1 ecrecover | address batch (one thread per sig) | ~415 us/sig (ecrecover + keccak) | 65 ms at N=128 (0.89x); 71 ms at N=160 (0.96x); 70 ms at N=168 (1.01x) | **N=168** | gate at n>=168; below this stay on CPU loop |
| BLS aggregate verify | same-msg batch (CPU host blst, pubkey-cache hot path) | flat 1.15 ms/sig | 1.13x at n=1; 9.00x at n=16; 16.51x at n=1024 | **n=16** (CPU-only path; pubkey cache + blst) | already gated; landed in cevm v0.46.2 |
| BLS aggregate verify | general-msg batch (CPU host blst) | 1.15 ms/sig flat | 1.21x at n=1; 2.51x at n=16; 2.65x at n=128; 2.67x at n=1024 | **n=16** (CPU-only path) | already gated |
| BLS single pairing | e(P,Q) | 510 us (blst host) | ~475 ms on Metal (~930x slower) | **never** within sampled range | CPU-only on M1; CUDA SoTA path; structural limit (606 dispatches per pairing, 1 of 32 SIMD lanes utilised) |
| Quasar substrate (consensus full-round) | end-to-end Metal vs CPU reference | 0.026 - 6.0 ms across N={16, 64, 256, 1024, 2048, 4096} | 0.003x - 0.011x at every N within envelope | **never** within 4096-tx envelope | gate locked above envelope (`kQuasarSubstrateMetalThreshold = 8192`); routes to CPU on every production round |
| EVM bytecode kernel | V1 (1 thread/tx) | 28 M ops/sec (sequential CPU) | min 39 M ops/sec at N=1000-2000; 49 M ops/sec at N=5000 | **N~=2000** (1.5x); already wins at N=5000 (1.75x) | gate at n>=2000 (V1); V2 32-thread/tx FAILs byte-equality on M1, do not gate |
| AIVM FullRound (keccak-chain transition) | end-to-end | 1.36 - 40.7 ms across small/medium/large/xlarge | 26.5 - 706 ms (0.05x - 0.06x at every size) | **never** within sampled range | CPU-only on M1; dGPU-ready architecture (per-thread parallelism) |

## Acceleration kernels (LP-160..LP-166)

Seven acceleration kernels shipped 2026-04-28 under the canonical
three-backend layout (Metal / CUDA / WGSL + CPU oracle). Numbers below
are CPU-side measurements on the same Apple M1 Max host as the rest of
this file unless otherwise noted; per-backend GPU numbers land in CI
on the `hanzo-build-linux-amd64` runner with `CRYPTO_HAS_CUDA=1` /
`CRYPTO_HAS_DAWN=1` and feed back into this table as they arrive.

| LP | Kernel | CPU baseline | LP path | Crossover / ratio | Source |
|----|--------|-------------|---------|---|---|
| LP-160 | secp256k1 / BN254 / BLS12-381 / Banderwagon batch Fp inversion | N independent Fermat exps | 1 inv + 3·(N-1) muls | `N* = 8` (Metal), `N* = 16` (CUDA), `N* = 32` (WGSL); 14× at N=1024 on M1 Max Metal | `secp256k1/test/batch_inv_*_test`; commit `856b9a35` (CUDA+WGSL port) |
| LP-161 | Multi-curve Pippenger MSM | per-curve scalar-mul + accumulate | one templated kernel via `curve_traits<C>` | KAT 22/22 pass on first commit (8 secp256k1 incl. n=0, 7 BN254, 7 Banderwagon, 1 BLS12-381 NOTIMPL contract test); KAT lifts to **29/29** when the BLS12-381 G1 first-party body lands (header-only adapter is in place at `gpukit/curve_traits/bls12_381_g1_traits.h`) | `gpukit/test/multi_pippenger_test`; commit `741f7c3f` |
| LP-162 | BLS12-381 combined-pair Miller loop (k pairs fused) | k independent Miller dispatches + Fp12 product | 1 fused dispatch | **9.50×** at k=1024 (BridgeVM v0.60 measured); `k* = 2` | `bls/test/bls_combined_miller_*_test`; commit `2fede848` |
| LP-163 | Karatsuba bigint modexp | intx CIOS schoolbook | recursive 3-mul split + Karatsuba-SOS | mul-only: **1.34×** at 2048-bit, **1.26×** at 4096-bit; end-to-end RSA-e=65537 modexp: **0.99×** at 1024-bit, **0.29×** at 2048-bit (CIOS still wins), **1.93×** at 4096-bit (Karatsuba-SOS wins). `K_THRESHOLD = 32 limbs (2048 bits)` | `modexp/test/modexp_karatsuba_bench`; commit `f35eedd2` (Paillier 2048-bit consumer) |
| LP-164 | Six-step lattice NTT (Bailey 1990) | radix-2 Cooley-Tukey ceiling at N=2^16 | √N · √N factor + transpose | **6–9 Mops/s** at N=2^20 single-thread CPU (Apple M2 Ultra); cross-backend GPU equality validated structurally on macOS via the CPU-fallthrough oracle. Crossover: `N ≤ 2^13` schoolbook, `2^14–2^16` radix-2, `2^17–2^20` six-step | `ntt/test/ntt_large_test`; commit `8d058ded` (consumer hooks via poly_mul) |
| LP-165 | Pedersen width-256 tree-reduce vector commit | sequential 256-step accumulator (linear loop) | `log₂(256) = 8`-depth pairwise reduction in shared memory | Apple M2 Ultra Metal: **0.73×** (3 814 µs tree-reduce vs 2 774 µs legacy two-stage — Apple's 24 KiB threadgroup memory caps occupancy at width 256). Wins on devices with 192 KiB shared memory per SM (NVIDIA A100 / H100). CPU stays linear (oracle). `w* = 8` for the GPU path | `pedersen/test/pedersen_tree_*_determinism_test`; commit `8d058ded` |
| LP-166 | FROST + CGGMP21 batched threshold pre-signing | sequential per-slot pre-sign (MPCVM v0.62) | M·N parallel pre-signatures in one dispatch | FROST: **6/6** `frost_presign_test` pass on commit `8e8fb102`; 128 commitments/s × 2 backends at M=10 N=64 locally. CGGMP21: **4/4** `cggmp21_presign_test` pass on commit `f35eedd2` (full 2048-bit Paillier + Π^enc + LP-163 Karatsuba 4096-bit modexp). Projected **5.0–7.2×** at M=7 N=64 vs sequential | `frost/test/frost_presign_test`, `cggmp21/test/cggmp21_presign_test`; commits `debeab78` (FROST aggregate+verify), `f35eedd2` (Paillier) |

The 2048-bit modexp end-to-end ratio (0.29×) is the honest CIOS-still-wins
zone: Karatsuba mul wins inside the limb product (1.34×), but the
Karatsuba-SOS reduction wrapper at 32 limbs spends its savings on
higher per-step bookkeeping vs the tighter CIOS Montgomery loop. The
4096-bit row is where Karatsuba pulls ahead end-to-end (1.93×) — that
is the RSA-4096-attestation hot path the LP-163 spec targets, and
where the Paillier 2048-bit ciphertext arithmetic (Z_{N²} at N²≈4096
bits) lives.

The multi-pippenger 22/22 KAT pass on first commit is the BLS12-381
NOTIMPL-contract test passing alongside three real curves; the
header-only `bls12_381_g1_traits.h` adapter is in place and activates
under `GPUKIT_MP_HAS_BLS12_381_G1=1` once a first-party (no-blst) BLS
G1 Jacobian + Pippenger body lands. At that point the bls_notimpl
contract test flips to a real KAT and the count goes to 29/29.

## Substrate-wide context

The QuasarGPUEngine substrate is structurally never beating CPU on M1 Max
within the per-round ingress envelope of 4096 tx. The wave-tick scheduler
floor is ~554 ms at N=4096 vs CPU 6.0 ms. The substrate Metal threshold
is therefore set above the envelope:

```cpp
// cevm/lib/consensus/quasar/gpu/quasar_gpu_engine.hpp:70
constexpr uint32_t kQuasarSubstrateMetalThreshold = 8192u;
```

In production this gate falls through to the CPU reference on every
sized round. The Metal substrate exists for two reasons orthogonal to
single-host throughput:

1. **dGPU acceleration** — on Linux+CUDA hosts (dispatch latency ~10 us
   not ~1 ms) the architectural split shows the per-thread parallelism
   speedup the substrate targets.
2. **Cross-backend determinism enforcement** — three independent GPU
   implementations (Metal, WGSL, CUDA) that must agree byte-for-byte
   with the CPU oracle are the mechanism that catches consensus-level
   bugs in any single backend.

The pre-existing `Threshold*` constants in
`kinet-labs/crypto/gpu/zk.go` are tuned for the same M1 envelope:

| Op | Threshold | Source |
|----|-----------|--------|
| Poseidon2 | 64 | kinet-labs/crypto/gpu/zk.go:53 |
| Merkle | 128 | kinet-labs/crypto/gpu/zk.go:54 |
| MSM | 256 | kinet-labs/crypto/gpu/zk.go:55 |
| Commitment | 128 | kinet-labs/crypto/gpu/zk.go:56 |
| FRI | 512 | kinet-labs/crypto/gpu/zk.go:57 |

These constants are set without per-primitive sweep data on the same
hardware; the empirical sweep that would calibrate them lives in
follow-on work (no Metal kernel + bench harness pair exists today for
Poseidon2 / Merkle / MSM / Commitment / FRI to drive a measurement).

## Primitives skipped

The following primitives have a Metal kernel today but no measurable
crossover (no bench harness or structurally never-wins on M1 Max):

- **secp256k1 batch_inv (Stage A on-device)** — driver dispatches single
  thread per kernel (`MTLSize(1,1,1)`) by design for byte-equality with
  CPU Montgomery batch inversion. Single-thread Metal will never beat
  single-thread CPU; the structural intent is to free the host CPU for
  other pipeline stages, not to outpace it. No crossover in N.
- **BLS Stage 5b single pairing** — 606 dispatches per pairing, ~10 us
  each on M1 Max, exceeds the 510 us blst host budget by 930x. Apple's
  MetalCompilerService cannot fuse the kernels (see
  `bls_miller.metal:268-277` and `bls_final_exp.metal:18-32`). Karabina
  compressed cyclotomic squarings (algorithmic) or CUDA dispatch (lower
  latency) are the SoTA paths.

## Primitives lacking measurable Metal performance

- **Poseidon2** — Metal driver exists at
  `crypto/poseidon/gpu/metal/poseidon2_driver.{h,mm}` and links into
  `libposeidon_metal.a`. No bench harness; no Metal-vs-CPU sweep
  data on the same hardware.
- **IPA** — Metal driver exists at `crypto/ipa/gpu/metal/ipa_driver.mm`
  and links into `libipa_metal.a`. No bench harness.
- **Polynomial multiplication** — Metal kernel at
  `crypto/poly_mul/gpu/metal/poly_mul.metal` builds into
  `libpoly_mul.a`. No driver / no harness.
- **gpukit primitives** (NTT, prefix_sum, radix_sort, batch_inversion,
  merkle_compose, transcript_root, compaction) — Metal drivers exist
  in `crypto/gpukit/gpu/metal/`. Sibling LP-137 work in progress; no
  per-primitive bench harness yet.

## Primitives skipped (sibling-shipping)

The sibling agent on issue #87 is shipping new Metal kernels for the
following primitives. Their drivers + tests are visible in
`kinet-labs/crypto/build-v064/` but they were not benched here because the
sibling's harness is the canonical one, and the Metal pipelines are
in fkinet:

- **SHA-256** (`crypto/sha256/gpu/metal/sha256_batch_*`)
- **RIPEMD-160** (`crypto/ripemd160/gpu/metal/ripemd160_batch_*`)
- **BLAKE2b** (`crypto/blake2b/gpu/metal/blake2b_batch_*`)

Crossover thresholds for these primitives land in the sibling's bench.

## Methodology

### Reproduction (Keccak)

```
cd /Users/z/work/kinet-labs/cevm
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DKINET_CEVM_ENABLE_METAL=ON
cmake --build build -j 8

# Build the sweep harness:
clang++ -std=c++20 -O3 -DNDEBUG \
  -I/Users/z/work/kinet-labs/cevm/lib/evm/gpu/metal \
  -I/Users/z/work/kinet-labs/cevm/lib/cevm_precompiles \
  -framework Metal -framework Foundation \
  /tmp/kinet-bench/keccak_sweep.cpp \
  build/lib/evm/CMakeFiles/evm-metal-hosts.dir/gpu/metal/keccak_host.mm.o \
  build/lib/cevm_precompiles/CMakeFiles/cevm_precompiles.dir/keccak.c.o \
  -o /tmp/kinet-bench/keccak_sweep

/tmp/kinet-bench/keccak_sweep 1 4 16 64 256 1024 4096 8192 16384 65536
```

### Reproduction (FHE NTT)

```
cd /Users/z/work/kinet-labs/fhe
cmake -S . -B build-mlx -DCMAKE_BUILD_TYPE=Release -DWITH_MLX=ON
cmake --build build-mlx -j 8 --target metal_ntt_bench
./build-mlx/src/core/lib/math/hal/mlx/metal_ntt_bench
```

Output stored in `kinet-labs/fhe/BENCHMARKS_METAL_NTT.txt` (regenerated this
pass; matches `kinet-labs/fhe/BENCHMARKS.md` table at N=4096 B=128 = 14.02x).

### Reproduction (BLS aggregate verify, host blst CPU path)

```
cd /Users/z/work/kinet-labs/cevm
cmake --build build -j 8 --target precompiles-bench
./build/precompiles-bench
```

Cache warm methodology: one untimed pass through
`verify_bls_same_message_batch` populates the pubkey-affine cache with
the current N pubkeys, then `runs` warm passes are timed. Min over
100/30/10/5 runs at n=1/16/128/1024.

### Reproduction (secp256k1 ecrecover address batch Metal)

```
cd /Users/z/work/kinet-labs/crypto
cmake -S . -B build-v063 -DCMAKE_BUILD_TYPE=Release -DCRYPTO_BUILD_TESTS=ON
cmake --build build-v063 -j 8

# Build the sweep harness:
clang++ -std=c++20 -O3 -DNDEBUG \
  -I/Users/z/work/kinet-labs/crypto/include \
  -framework Metal -framework Foundation \
  /tmp/kinet-bench/ecrecover_sweep.cpp \
  build-v063/secp256k1/libsecp256k1.a \
  build-v063/secp256k1/libsecp256k1_cpu.a \
  build-v063/secp256k1/libsecp256k1_metal.a \
  build-v063/keccak/libkeccak.a \
  build-v063/keccak/libkeccak_cpu.a \
  -o /tmp/kinet-bench/ecrecover_sweep

CRYPTO_SECP256K1_METALLIB=$(pwd)/build-v063/kinet_crypto_secp256k1.metallib \
  /tmp/kinet-bench/ecrecover_sweep 1 4 16 64 128 168 192 256 1024 4096 16384
```

### Reproduction (Quasar substrate threshold sweep)

```
cd /Users/z/work/kinet-labs/cevm
cmake --build build -j 8 --target quasar-threshold-sweep
./build/lib/evm/quasar-threshold-sweep
```

The sweep walks N over {16, 64, 256, 1024, 2048, 4096}; on M1 Max the
substrate Metal path is 0.003x - 0.011x of CPU at every sampled N.

### Reproduction (EVM bytecode kernel V1)

```
cd /Users/z/work/kinet-labs/cevm
cmake --build build-bench -j 8 --target evm-bench-kernel
./build-bench/lib/evm/evm-bench-kernel <N> <iters/tx> <runs>
```

Sweep N=64, 256, 1024, 2000, 5000 at iters/tx=30, runs=5.

## Honest residual

Single-pairing parity with blst on Metal is not reachable without
algorithmic changes. The Metal substrate's per-dispatch floor on M1 Max
(~10 us per dispatch warm, ~250 us cold) and per-kernel-launch overhead
(~150 us for a single command-buffer commit) places a hard floor below
which dispatch-bound kernels cannot cross. Primitives that cross this
floor are those where the per-batch arithmetic dwarfs dispatch (FHE NTT
B=128, secp256k1 ecrecover N>=168, Keccak N>=6144); primitives that do
not (single pairing, substrate-only consensus rounds, EVM-V1 at N<2000,
AIVM FullRound at all sizes) are CPU-only on this hardware and gain
GPU acceleration only on dGPU hosts (CUDA, dispatch ~10 us).

## Sources

- `kinet-labs/cevm/BENCHMARKS.md` (v0.45 - v0.47.2 BLS / V2 EVM kernel rows)
- `kinet-labs/cevm/BENCHMARKS_V045.txt`, `BENCHMARKS_V046_2.txt`,
  `BENCHMARKS_V0472.txt`
- `kinet-labs/cevm/lib/consensus/quasar/gpu/quasar_gpu_engine.hpp:70`
  (substrate threshold)
- `kinet-labs/crypto/bls/test/STAGE5_PERFORMANCE.md` (single-pairing
  structural limit)
- `kinet-labs/fhe/BENCHMARKS.md` and `BENCHMARKS_METAL_NTT.txt`
- `kinet-labs/aivm/BENCHMARKS.md` (FullRound 0.05x - 0.06x at every size)
- `kinet-labs/crypto/gpu/zk.go:32-47` and `kinet-labs/crypto/LLM.md:1527-1531`
  (Threshold* constants)
- Sweep harnesses at `/tmp/kinet-bench/keccak_sweep.cpp` and
  `/tmp/kinet-bench/ecrecover_sweep.cpp` (this pass)

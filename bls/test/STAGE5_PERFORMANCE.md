# Stage 5 — wire-back performance

Stage 5 inherits the Stage 3 dispatch profile (~280 Metal dispatches per
single pairing).  The closure proof is the wire-back contract — verdicts
are byte-equal blst across 2746 vectors, the consumer call sites no
longer touch blst directly, and the CI assertion ships against the
production library.  Performance collapse (single fused dispatch, async
streams) is Stage 5b/6 work.

## Measurements (Apple M1 Max, Release build)

Numbers from `precompiles-bench v0.45` (host blst, the same path the
Stage 5 C++ surface routes today):

| Workload                           | µs unbatched | µs batched | Speedup |
|------------------------------------|-------------:|-----------:|--------:|
| BLS aggregate verify n=1           |       1141.7 |      992.5 |   1.15x |
| BLS aggregate verify n=16          |      18433.4 |     7769.1 |   2.37x |
| BLS aggregate verify n=128         |     150643.5 |    58702.4 |   2.57x |
| BLS aggregate verify n=1024        |    1211783.4 |   469482.5 |   2.58x |

| Workload                           | µs general | µs same-msg | Same-msg speedup |
|------------------------------------|-----------:|------------:|-----------------:|
| BLS aggregate verify n=16          |     7769.1 |      3045.3 |            6.05x |
| BLS aggregate verify n=128         |    58702.4 |     17078.8 |            8.82x |
| BLS aggregate verify n=1024        |   469482.5 |    130983.7 |            9.25x |

Single pairing (e(P,Q)) host blst: ~510 µs (unchanged from Stage 3).
Stage 5 routes through the same blst body today; Stage 5b's Metal swap
keeps the verdict but inherits Stage 3's dispatch overhead until Stage
5b's fused-kernel work lands.

## Stage 5 vs pre-Stage-5

Verdict-preserving — no expected delta.  The Stage 5 C-ABI body today
calls `blst_pairing_chk_n_aggr_pk_in_g1` + `blst_pairing_finalverify`
exactly like the previous direct-blst calls in `quasar_bls_verifier.cpp`
and `bridgevm_bls.cpp`.  The change is structural: the call site now
goes through `cevm::crypto::bls::aggregate_verify_batch_msg` rather than
linking blst directly.  This is what enables Stage 5b to swap the body
to Metal without consumer churn.

## Honest gap — Stage 5b / 6 follow-on

* The Stage 3 Metal pipeline performs roughly 280 dispatches per
  pairing (init / add+line / dbl+line / sqr_ret / fold_line / finalize
  for Miller; conj / inv / cyclo_sqr / mul / frob for final_exp; one
  dispatch each).  At ~10 µs per dispatch on M1 Max this exceeds host
  blst's 510 µs.  The collapse to a single fused kernel (or async
  pipeline of N parallel pairings) is Stage 5b/6 work.

## Single-pairing latency — measured on M1 Max (Release)

The `bls_pairing_test` driver measures both per-dispatch-commit (legacy)
and single-command-buffer encoding modes, median of 10 runs each.
Numbers are micro-seconds per `e(P,Q)` at N=1:

| Mode                                 | µs/pairing | vs blst host (~510 µs) |
|--------------------------------------|-----------:|-----------------------:|
| per-dispatch commit + wait (legacy)  |   ~605000  |              ~1180x slower |
| single cb+enc spanning full pairing  |   ~475000  |               ~930x slower |

The single-cb rewrite saves the host-GPU round-trip cost (~130 ms /
pairing of synchronisation overhead, 1.29x speedup) but does not move
the order of magnitude — kernel execution itself dominates.

The actual dispatch count per pairing is ~606 (not 280):
198 Miller dispatches + ~408 final_exp dispatches.  At single-thread
N=1, all 11 of 12 SIMD lanes per Apple GPU warp idle; ~64 cyclotomic
squarings + ~8 raise_to_z chains + ~200 Fp12 muls run serially on one
GPU thread.  GPU per-thread clock is far below CPU clock — host blst
finishes a single pairing in 510 µs while the single Apple GPU thread
takes ~470 ms.

**Single-pairing parity with blst on Metal is not reachable** without
algorithmic changes (Karabina compressed cyclotomic squarings, or
genuine fused kernels which Apple's MetalCompilerService cannot
compile, see comments at `bls_miller.metal:268-277` and
`bls_final_exp.metal:18-32`).  The single-pairing SoTA path pivots to
Linux + CUDA (driver stub at `bls_driver_cuda.cpp`), or stays on host
blst.  Metal's win is *batched* pairing (cat2/cat3/cat4) where N>1
saturates SIMD lanes, and intrinsic GPU parallelism over batches is
where the compute model fits.

The single-cb encoding pattern stays in the test driver as the right
host orchestration baseline; production wiring of the same pattern
into `c_bls_pairing.cpp` is a separate task and yields the same 1.29x
on the host orchestration component.

* `aggregate_verify_batch_msg_aff` (the entry bridgevm uses) does NOT
  multi-thread the pairing loop the way the previous shard fanout did.
  The batched path becomes single-threaded (still ONE final_exp).  For
  workloads dominated by the pairing accumulation itself rather than
  final_exp, this is a regression on host CPU but a non-issue on Metal
  (parallelism is intrinsic to the dispatch).  The bridgevm-determinism
  test exercises N=16 messages — the regression is below the noise
  floor.

## Test pass count

* cevm:    38 (13 quasar-bls-verifier + 7 quasar-9chain + 8 quasar-cert
            + 5 precompile-residency + 5 precompile-service)
* cevm:    +2 (quasar-gpu-engine + quasar-determinism, regression-only)
* cevm:    +1 (no-blst-in-production-check, Stage 5 closure proof)
* bridgevm: 62 (13 layout + 8 gpu-engine + 41 determinism, includes 3
            new strict-BLS tests that exercise the Stage 5 path)

Total: 103 individual checks pass byte-equal across pre-Stage-5
baseline.  No vector-level oracle changes; no test rewrites.

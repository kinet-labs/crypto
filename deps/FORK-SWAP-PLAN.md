# kinet-labs-deps fork-swap plan

This branch (`fork-swap-kinet-labs-deps-2026-04-27`) lands the FetchContent swap for
the two deps that have **no in-flight conflict** at the time of authoring:

* `deps/intx/`     → FetchContent `kinet-labs/intx@v0.15.0`
* `deps/evmmax/`   → FetchContent `kinet-labs/evmmax@v0.21.0`

## Forks created (canonical kinet-labs org)

| Upstream | kinet-labs fork | Pin |
|---|---|---|
| supranational/blst | github.com/kinet-labs/blst | v0.3.15 |
| PQClean/PQClean | github.com/kinet-labs/pqclean | master @ 3730b32a |
| ethereum/c-kzg-4844 | github.com/kinet-labs/c-kzg-4844 | v2.1.7 |
| crate-crypto/go-ipa | github.com/kinet-labs/go-ipa | master @ 53bbb0ce |
| ethereum/go-verkle | github.com/kinet-labs/go-verkle | v0.2.2 |
| BLAKE3-team/BLAKE3 | github.com/kinet-labs/blake3 | 1.8.5 |
| chfast/intx | github.com/kinet-labs/intx | v0.15.0 |
| ethereum/evmone | github.com/kinet-labs/evmmax | v0.21.0 |

Each fork has `KINETFI-FORK.md` at the root with the sync policy.

## Pending swaps (waiting for sibling agents to land)

Land these swaps **after** the corresponding sibling work merges. Do NOT swap
inline against an in-flight tree — coordinate via the LP-137 issue thread.

| Sibling | Files to swap | Target fork |
|---|---|---|
| #102 (PQClean port) | `mldsa/CMakeLists.txt`, `mlkem/CMakeLists.txt`, `slhdsa/CMakeLists.txt` | kinet-labs/pqclean |
| #103 (KZG)          | `kzg/CMakeLists.txt`, `evm256/CMakeLists.txt` | kinet-labs/c-kzg-4844 |
| #104 (IPA/Verkle)   | `verkle/CMakeLists.txt` (DeterministicGenerator KATs), `ipa/CMakeLists.txt` (KAT source) | kinet-labs/go-ipa, kinet-labs/go-verkle |
| (any time)          | `blake3/test/CMakeLists.txt` (KAT vectors when test/ is created) | kinet-labs/blake3 |
| (test-oracle)       | `bls/test/cmake/blst.cmake` already references blst test-oracle; swap URL to kinet-labs/blst | kinet-labs/blst |

## Procedure for each pending swap

```cmake
include(FetchContent)
FetchContent_Declare(kinet-labs_<name>
    GIT_REPOSITORY https://github.com/kinet-labs/<name>.git
    GIT_TAG        <pinned-tag-or-sha>
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(kinet-labs_<name>)
```

Then point the consumer at `${kinet-labs_<name>_SOURCE_DIR}` for the path of the
header / KAT vector / asset needed. Never include upstream's own targets if a
header-only INTERFACE alias suffices — keeps link surface clean per LP-137.

## Sync policy

Forks track upstream tagged releases only. Pulling upstream changes:

1. Create `sync/<tag>` branch on the fork.
2. Pull upstream into it. Audit the diff.
3. Re-run all kinet-labs/crypto KATs against the new pin.
4. Merge to fork's default branch only if KATs pass.
5. Update `GIT_TAG` in the consuming `CMakeLists.txt` here.

Never track upstream HEAD. Never auto-merge upstream PRs.

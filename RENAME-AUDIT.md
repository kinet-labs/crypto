# Brand-neutral rename audit

Date: 2026-04-26

## Rule

Brand stays in import path only. Symbols, env, exports, error codes are brand-neutral.

`github.com/kinet-labs/crypto`, `<kinet/crypto/keccak.h>`, `use kinetcrypto::*` — paths can carry brand. Symbols inside cannot.

## Scope

- `/Users/z/work/kinet/crypto/`     (Go module + Rust/TS/Python bindings)
- `/Users/z/work/kinet-labs/crypto/`  (C/C++/GPU canonical)
- `/Users/z/work/kinet/accel/`      (Go GPU shim)

Out of scope: per-VM dirs (cevm, platformvm, xvm, aivm, mpcvm, bridgevm), other kinet-labs subprojects (kinet-accel, install), CMake variables, library file names, Pedersen domain-separation tags.

## Mapping — env

| Old | New |
|---|---|
| `KINET_CRYPTO_BACKEND` | `CRYPTO_BACKEND` |
| `KINET_CRYPTO_DIR` | `CRYPTO_DIR` |
| `KINET_CRYPTO_BUILD_DIR` | `CRYPTO_BUILD_DIR` |
| `KINET_CRYPTO_LIB_DIR` | `CRYPTO_LIB_DIR` |
| `KINET_CRYPTO_LIB` | `CRYPTO_LIB` |
| `KINET_GPU_BACKEND` | `GPU_BACKEND` |
| `KINET_BACKEND` | `GPU_BACKEND` (unify; same purpose) |
| `KINET_ACCEL_BACKEND` | `GPU_BACKEND` (unify; same purpose) |
| `KINET_PLUGIN_PATH` | `PLUGIN_PATH` |
| `KINET_TESTNET_RPC` | `TESTNET_RPC` |
| `KINET_MAINNET_RPC` | `MAINNET_RPC` |
| `CRYPTO_SECP256K1_METALLIB` | `SECP256K1_METALLIB` |

Backwards-compat: read new name first; on miss, read old name with deprecation warning. One transition release. Drop next.

## Mapping — kinet-labs/crypto C-ABI symbols

Algorithm functions: drop `kinet_` prefix entirely. Algorithm name is its own namespace.

| Old | New |
|---|---|
| `kinet_keccak256(...)` | `keccak256(...)` |
| `kinet_keccak256_batch(...)` | `keccak256_batch(...)` |
| `kinet_sha256(...)` | `sha256(...)` |
| `kinet_blake2b(...)` | `blake2b(...)` |
| `kinet_blake3(...)` | `blake3(...)` |
| `kinet_blake3_batch(...)` | `blake3_batch(...)` |
| `kinet_ripemd160(...)` | `ripemd160(...)` |
| `kinet_aead_chacha20poly1305_seal(...)` | `aead_chacha20poly1305_seal(...)` |
| `kinet_aead_chacha20poly1305_open(...)` | `aead_chacha20poly1305_open(...)` |
| `kinet_secp256k1_<op>(...)` | `secp256k1_<op>(...)` |
| `kinet_secp256r1_verify(...)` | `secp256r1_verify(...)` |
| `kinet_ed25519_<op>(...)` | `ed25519_<op>(...)` |
| `kinet_sr25519_<op>(...)` | `sr25519_<op>(...)` |
| `kinet_bn254_<op>(...)` | `bn254_<op>(...)` |
| `kinet_bls_<op>(...)` | `bls_<op>(...)` |
| `kinet_kzg_<op>(...)` | `kzg_<op>(...)` |
| `kinet_mldsa_<op>(...)` | `mldsa_<op>(...)` |
| `kinet_mlkem_<op>(...)` | `mlkem_<op>(...)` |
| `kinet_slhdsa_<op>(...)` | `slhdsa_<op>(...)` |
| `kinet_frost_<op>(...)` | `frost_<op>(...)` |
| `kinet_cggmp21_<op>(...)` | `cggmp21_<op>(...)` |
| `kinet_ringtail_<op>(...)` | `ringtail_<op>(...)` |
| `kinet_ipa_<op>(...)` | `ipa_<op>(...)` |
| `kinet_lamport_<op>(...)` | `lamport_<op>(...)` |
| `kinet_pedersen_<op>(...)` | `pedersen_<op>(...)` |
| `kinet_poseidon_<op>(...)` | `poseidon_<op>(...)` |
| `kinet_verkle_<op>(...)` | `verkle_<op>(...)` |
| `kinet_modexp(...)` | `modexp(...)` |
| `kinet_evm256_<op>(...)` | `evm256_<op>(...)` |
| `kinet_ntt_<op>(...)` | `ntt_<op>(...)` |
| `kinet_poly_mul(...)` | `poly_mul(...)` |
| `kinet_frost_ctx` | `frost_ctx` (typedef) |
| `kinet_cggmp21_ctx` | `cggmp21_ctx` (typedef) |
| `kinet_ringtail_ctx` | `ringtail_ctx` (typedef) |
| `kinet_secp256k1_status` (typedef) | `secp256k1_status` (typedef) |

GPU control plane functions: prefix is `crypto_gpu_*` (drop `kinet_`, keep `crypto_gpu_` namespace since these are top-level dispatcher concerns, not algorithm-scoped).

| Old | New |
|---|---|
| `kinet_crypto_gpu_available(...)` | `crypto_gpu_available(...)` |
| `kinet_crypto_gpu_set_default(...)` | `crypto_gpu_set_default(...)` |
| `kinet_crypto_gpu_get_default(...)` | `crypto_gpu_get_default(...)` |
| `kinet_crypto_version(...)` | `crypto_version(...)` |

Status macros: namespace under `CRYPTO_*` to avoid collision with `OK`/`ERR_*` from anywhere else.

| Old | New |
|---|---|
| `KINET_OK` | `CRYPTO_OK` |
| `KINET_ERR_INPUT` | `CRYPTO_ERR_INPUT` |
| `KINET_ERR_LENGTH` | `CRYPTO_ERR_LENGTH` |
| `KINET_ERR_VERIFY` | `CRYPTO_ERR_VERIFY` |
| `KINET_ERR_BACKEND` | `CRYPTO_ERR_BACKEND` |
| `KINET_ERR_NOTIMPL` | `CRYPTO_ERR_NOTIMPL` |
| `KINET_ERR_INTERNAL` | `CRYPTO_ERR_INTERNAL` |
| `KINET_BACKEND_CPU` | `CRYPTO_BACKEND_CPU` |
| `KINET_BACKEND_CUDA` | `CRYPTO_BACKEND_CUDA` |
| `KINET_BACKEND_METAL` | `CRYPTO_BACKEND_METAL` |
| `KINET_BACKEND_WGSL` | `CRYPTO_BACKEND_WGSL` |
| `KINET_SECP256K1_OK` | `SECP256K1_OK` (algorithm-namespaced) |
| `KINET_SECP256K1_ERR_*` | `SECP256K1_ERR_*` |

Header guards: keep `KINET_*` macros (e.g. `KINET_CRYPTO_KECCAK_H`) — these are file-private and never leak. No-op rename.

## Mapping — kinet-labs/crypto/include/kinet/crypto/crypto.h (fat API)

This is a parallel surface using `kinet_crypto_*` prefix. Drop the `kinet_` prefix → `crypto_*`.

| Old | New |
|---|---|
| `kinet_crypto_gpu_available()` | `crypto_gpu_available()` (already mapped above) |
| `kinet_crypto_get_backend()` | `crypto_get_backend()` |
| `kinet_crypto_clear_cache()` | `crypto_clear_cache()` |
| `kinet_crypto_bls_<op>(...)` | `crypto_bls_<op>(...)` |
| `kinet_crypto_mldsa_<op>(...)` | `crypto_mldsa_<op>(...)` |
| `kinet_crypto_threshold_<op>(...)` | `crypto_threshold_<op>(...)` |
| `kinet_crypto_sha3_*(...)` | `crypto_sha3_*(...)` |
| `kinet_crypto_blake3(...)` | `crypto_blake3(...)` |
| `kinet_crypto_batch_hash(...)` | `crypto_batch_hash(...)` |
| `kinet_crypto_consensus_verify_block(...)` | `crypto_consensus_verify_block(...)` |
| `KinetCryptoThresholdContext` | `CryptoThresholdContext` |
| `KINET_CRYPTO_SUCCESS`, `KINET_CRYPTO_ERROR_*` | `CRYPTO_SUCCESS`, `CRYPTO_ERROR_*` |

Note: "Backward compatibility aliases" already in `crypto.h` (lines 381-389) defined `CRYPTO_*` as aliases to `KINET_CRYPTO_*`. After rename: drop the aliases, `CRYPTO_*` becomes canonical.

## Mapping — kinet/accel C-API + CGO

The kinet/accel package has its own `c_api.h`. Symbols here use `accel_*` namespace (the package layer name, brand-neutral).

| Old | New |
|---|---|
| `kinet_status` (typedef) | `accel_status` |
| `kinet_session` (typedef) | `accel_session` |
| `kinet_tensor` (typedef) | `accel_tensor` |
| `kinet_dtype` (typedef) | `accel_dtype` |
| `kinet_backend_type` (typedef) | `accel_backend_type` |
| `kinet_device_info` (struct) | `accel_device_info` |
| `kinet_init(...)` | `accel_init(...)` |
| `kinet_shutdown(...)` | `accel_shutdown(...)` |
| `kinet_version(...)` | `accel_version(...)` |
| `kinet_get_error(...)` | `accel_get_error(...)` |
| `kinet_load_backend(...)` | `accel_load_backend(...)` |
| `kinet_backend_count(...)` | `accel_backend_count(...)` |
| `kinet_backend_type_at(...)` | `accel_backend_type_at(...)` |
| `kinet_device_count(...)` | `accel_device_count(...)` |
| `kinet_get_device_info(...)` | `accel_get_device_info(...)` |
| `kinet_session_<op>(...)` | `accel_session_<op>(...)` |
| `kinet_tensor_<op>(...)` | `accel_tensor_<op>(...)` |
| `kinet_<ml-or-crypto-op>(...)` | `accel_<op>(...)` |
| `KINET_OK`, `KINET_ERROR`, `KINET_*` | `ACCEL_OK`, `ACCEL_ERROR`, `ACCEL_*` |

## Mapping — Rust constants

`kinet/crypto/rust/sys/src/lib.rs` — replace `pub const KINET_SECP256K1_*` with idiomatic Rust enum.

```rust
#[repr(i32)]
pub enum Secp256k1Status {
    Ok = 0,
    InvalidR = 1,
    InvalidS = 2,
    InvalidV = 3,
    NoSqrt = 4,
    AtInfinity = 5,
    NullArg = 6,
    BufferLen = 7,
}
```

extern fn declarations: drop `kinet_` from `kinet_secp256k1_*` to match new C symbol names.

## Mapping — TypeScript exports

| Old | New |
|---|---|
| `KINET_CRYPTO_AVAILABLE` (export) | `cryptoAvailable` |
| `process.env.KINET_CRYPTO_LIB` | `process.env.CRYPTO_LIB` |

FFI symbol names inside `koffi.func(...)` strings: drop `kinet_` from C symbol names to match new ABI.

## Mapping — Python exports

| Old | New |
|---|---|
| `KINET_CRYPTO_AVAILABLE` (export) | `crypto_available` |
| `os.environ.get("KINET_CRYPTO_LIB")` | `os.environ.get("CRYPTO_LIB")` |

## Untouched

- Pedersen domain-separation tags `KINET_PEDERSEN_G`/`KINET_PEDERSEN_H` in `pedersen.go:44-48` — deployed contracts depend on byte values. Documented in code.
- Header guards `#ifndef KINET_*_H` — file-private, no leakage.
- CMake variables `CRYPTO_ENABLE_*`, `CRYPTO_BUILD_TESTS`, `CRYPTO_ALGS`, `CRYPTO_HAS_*` — build-system, not user-facing.
- Library file names `libkinetcrypto.*`, `libkinet_*` — path-level, opt-in.
- `KinetLibrary.cmake`, `KinetAlgorithm.cmake` internal vars (`KINET_NAME`, `KINET_VERSION`, etc.) — CMake function locals.
- Plugin file names `kinet_metal.plugin`, `kinet_webgpu.plugin`, `kinet_cuda.plugin` — file paths.
- Plugin search paths `/usr/local/lib/kinet/plugins`, `~/.kinet/plugins` — file paths.

## Files modified (counts)

### kinet/crypto (16 files)
- `backend/backend.go` — env read shim
- `backend/backend_test.go` — env name
- `backend/integration_test.go` — comment
- `bindings/python/kinetcrypto/__init__.py` — export
- `bindings/python/kinetcrypto/_ffi.py` — env name + export
- `bindings/typescript/src/index.ts` — export
- `bindings/typescript/src/test.ts` — export
- `bindings/typescript/src/ffi.ts` — env name + export, FFI symbol names
- `bindings/rust/build.rs` — env name
- `rust/sys/src/lib.rs` — enum migration
- `rust/sys/build.rs` — env names
- `rust/sys/Cargo.toml` — comments
- `precompile/test/Makefile` — env name
- `precompile/test/foundry.toml` — env names
- `pedersen/pedersen.go` — comment only (tags untouched)
- `AUDIT.md` — env name

### kinet-labs/crypto (~40 files)
- `c-abi/crypto.h` — symbol decls + macros
- `c-abi/c_crypto.cpp` — backend macros
- `include/kinet/crypto/secp256k1.h` — enum/decls
- `include/kinet/crypto/keccak.h` — decls
- `include/kinet/crypto/crypto.h` — fat API symbols + macros
- `secp256k1/c-abi/c_secp256k1.cpp`
- `secp256k1/cpp/ecrecover.cpp`
- `secp256k1/test/secp256k1_test.cpp`
- `secp256k1/test/secp256k1_gpu_test.cpp`
- `secp256k1/gpu/metal/secp256k1_first_party_driver.mm`
- `keccak/c-abi/c_keccak.cpp`
- `keccak/c-abi/c_keccak.h`
- `keccak/cpp/keccak.cpp`
- `keccak/test/keccak_test.cpp`
- `sha256/c-abi/c_sha256.cpp`
- `blake2b/c-abi/c_blake2b.cpp`
- `blake3/c-abi/c_blake3.cpp`
- `ripemd160/c-abi/c_ripemd160.cpp`
- `aead/c-abi/c_aead.cpp`
- `bls/c-abi/c_bls.cpp`
- `bn254/c-abi/c_bn254.cpp`
- `cggmp21/c-abi/c_cggmp21.cpp`
- `ed25519/c-abi/c_ed25519.cpp`
- `evm256/c-abi/c_evm256.cpp`
- `frost/c-abi/c_frost.cpp`
- `ipa/c-abi/c_ipa.cpp`
- `kzg/c-abi/c_kzg.cpp`
- `lamport/c-abi/c_lamport.cpp`
- `mldsa/c-abi/c_mldsa.cpp`
- `mlkem/c-abi/c_mlkem.cpp`
- `modexp/c-abi/c_modexp.cpp`
- `ntt/c-abi/c_ntt.cpp`
- `pedersen/c-abi/c_pedersen.cpp`
- `poseidon/c-abi/c_poseidon.cpp`
- `ringtail/c-abi/c_ringtail.cpp`
- `secp256r1/c-abi/c_secp256r1.cpp`
- `slhdsa/c-abi/c_slhdsa.cpp`
- `sr25519/c-abi/c_sr25519.cpp`
- `verkle/c-abi/c_verkle.cpp`
- `MIGRATION.md` — env name
- `LLM.md` — symbol/env names

### kinet/accel (8 files)
- `doc.go` — env name
- `internal/capi/capi.go` — symbols + macros
- `internal/capi/stub.go` — symbols + macros
- `crypto_secp256k1_cgo.go` — env name + secp256k1 symbol names
- `session_c.go` — env name
- `ops/fhe/fhe.go` — env name (in comment)
- `ops/crypto/crypto.go` — env name (in comment)
- `include/kinet/accel/c_api.h` — header rename

The kinet-labs/crypto `KINET_FHE_*` constants in `ops/fhe/cgo.go` come from external `<kinet/fhe/c_api.h>` — out of scope (separate kinet-labs project).

cmake_minimum_required(VERSION 3.20)

# Default to Release so -O3 -DNDEBUG is on for dev/CI builds. Without this the
# unoptimized build runs ~100x slower (e.g. pedersen_tree_test: 382s → <30s on
# arm64 Apple silicon). Multi-config generators (Visual Studio, Xcode) pick
# their own per-config flags, so only set the single-config default.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        Debug Release RelWithDebInfo MinSizeRel)
endif()

project(kinet_crypto VERSION 1.0.0 LANGUAGES C CXX)

# Opt-in AddressSanitizer + UndefinedBehaviorSanitizer build for tests.
# Use: cmake -DCRYPTO_ENABLE_ASAN=ON .. && cmake --build .
option(CRYPTO_ENABLE_ASAN "AddressSanitizer + UBSan for tests" OFF)
if(CRYPTO_ENABLE_ASAN)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

# =============================================================================
# kinet-labs/crypto - canonical GPU-accelerated cryptographic primitives
# =============================================================================
#
# Layout (one directory per algorithm):
#
#   c-abi/crypto.h           public C ABI for Go cgo + Rust bindgen
#   c-abi/c_crypto.cpp       top-level dispatcher (GPU control + version)
#   include/kinet/crypto/<alg>.h   per-algorithm public C header
#   <alg>/cpp/                   first-party CPU implementation
#   <alg>/gpu/{cuda,metal,wgsl}  GPU kernels + drivers
#   <alg>/c-abi/c_<alg>.{h,cpp}  algorithm-internal C ABI shim
#   <alg>/test/                  CPU + GPU correctness + determinism tests
#
# 30 algorithms: aead attestation banderwagon blake2b blake3 bls bn254 cggmp21
#                ed25519 evm256 frost ipa keccak kzg lamport mldsa mlkem modexp
#                ntt pedersen poly_mul poseidon ringtail ripemd160 secp256k1
#                secp256r1 sha256 slhdsa sr25519 verkle
#
# Hard rules:
#   * No vendoring. Every implementation is first-party authored code.
#   * GPU output is byte-equal to CPU output across all backends.
#   * No stubs in production paths -- placeholders return CRYPTO_ERR_NOTIMPL and
#     are filled by Phase 3.
# =============================================================================

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(KinetAlgorithm)

# External deps (header-only, FetchContent from kinet-labs-maintained forks).
# Must be added before any algorithm subdir that #includes <intx/intx.hpp>
# or <evmmax/evmmax.hpp> (currently bn254, modexp).
add_subdirectory(deps)

option(CRYPTO_ENABLE_CUDA  "Build CUDA drivers"  OFF)
option(CRYPTO_ENABLE_METAL "Build Metal drivers" OFF)
option(CRYPTO_BUILD_TESTS  "Build crypto tests"  ON)

if(APPLE)
    set(CRYPTO_ENABLE_METAL ON CACHE BOOL "Build Metal drivers" FORCE)
endif()

# WGSL/wgpu-native is the cross-platform CI backend (Linux). On macOS arm64
# the canonical GPU backend is Metal; the WGSL drivers are conditionally
# excluded from the build unless wgpu-native is found locally. Auto-detect
# by looking for libwgpu_native; pass -DCRYPTO_ENABLE_WGSL=ON|OFF to force.
# The linux-amd64 CI lane (`crypto-cuda-tests.yml`) installs libwgpu_native.so
# under /usr/local before configure, so the cache var resolves to ON without
# the explicit -D flag. On darwin/arm64 dev hosts without wgpu-native this
# stays OFF and WGSL drivers/tests are excluded from the build entirely.
if(NOT DEFINED CRYPTO_ENABLE_WGSL)
    find_path(_CRYPTO_WGPU_INCLUDE webgpu.h
        HINTS /opt/homebrew/include /usr/local/include /usr/include)
    find_library(_CRYPTO_WGPU_LIB NAMES wgpu_native wgpu
        HINTS /opt/homebrew/lib /usr/local/lib /usr/lib)
    if(_CRYPTO_WGPU_INCLUDE AND _CRYPTO_WGPU_LIB)
        set(_CRYPTO_WGSL_DEFAULT ON)
        message(STATUS "WGSL: wgpu-native autodetected (${_CRYPTO_WGPU_LIB})")
    else()
        set(_CRYPTO_WGSL_DEFAULT OFF)
    endif()
    set(CRYPTO_ENABLE_WGSL ${_CRYPTO_WGSL_DEFAULT}
        CACHE BOOL "Build WGSL drivers")
endif()

if(CRYPTO_ENABLE_CUDA)
    enable_language(CUDA)
    add_compile_definitions(CRYPTO_HAS_CUDA=1)
endif()
if(CRYPTO_ENABLE_METAL)
    enable_language(OBJCXX)
    add_compile_definitions(CRYPTO_HAS_METAL=1)
endif()
# CRYPTO_ENABLE_WGSL is the compile-time inclusion gate for WGSL driver TUs
# and the test sites that call into them. CRYPTO_HAS_WGSL is the runtime
# environment flag used by the determinism harnesses to assert no skip.
if(CRYPTO_ENABLE_WGSL)
    add_compile_definitions(CRYPTO_ENABLE_WGSL=1 CRYPTO_HAS_WGSL=1)
else()
    add_compile_definitions(CRYPTO_ENABLE_WGSL=0)
endif()

# Public include dir reachable from every translation unit as
#   #include <crypto.h>           (umbrella surface)
#   #include <kinet/crypto/<alg>.h>     (per-algorithm surface)
include_directories(BEFORE
    ${CMAKE_CURRENT_SOURCE_DIR}/c-abi
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/attestation/include
)

# 29 canonical algorithms (alphabetical).
set(CRYPTO_ALGS
    aead
    attestation
    banderwagon
    blake2b
    blake3
    bls
    bn254
    cggmp21
    ed25519
    evm256
    frost
    ipa
    keccak
    kzg
    lamport
    mldsa
    mlkem
    modexp
    ntt
    pedersen
    poly_mul
    poseidon
    ringtail
    ripemd160
    secp256k1
    secp256r1
    sha256
    slhdsa
    sr25519
    verkle
)

foreach(_alg ${CRYPTO_ALGS})
    add_subdirectory(${_alg})
endforeach()

# pqclean_kat -- shared support library used only by the FIPS 203/204/205 KAT
# tests. Bundles PQClean's NIST AES-256-CTR DRBG (test/common/nistkatrng.c) +
# AES-256 ECB (common/aes.c). Letting the KAT test seed the DRBG with
# entropy_input[48] = 0..47 and reseed per-round is what makes the test
# byte-equal to PQClean's upstream nistkat.c output -- whose SHA-256 digest
# is the META.yml `nistkat-sha256` value vendored in pqclean_kat_digests.h.
# A small private SHA-256 (pqclean_kat_sha256.c, FIPS 180-4) is shipped to
# avoid colliding with kinet-labs's public C-ABI int sha256(...).
# NEVER linked into mldsa/mlkem/slhdsa production archives.
if(CRYPTO_BUILD_TESTS)
    add_library(pqclean_kat STATIC
        pqclean_kat/aes.c
        pqclean_kat/nistkatrng.c
        pqclean_kat/pqclean_kat_shim.c
        pqclean_kat/pqclean_kat_sha256.c
    )
    target_include_directories(pqclean_kat PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/pqclean_kat>)
    set_target_properties(pqclean_kat PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        C_STANDARD 99)
endif()

# gpukit -- common GPU kernel-pattern library (prefix_sum, compaction,
# radix_sort, batch_inversion, merkle_compose, transcript_root, ntt). Lives
# alongside the algorithms because it is a building-block layer they consume.
# Enable testing here so gpukit's add_test calls register with CTest (gpukit
# is add_subdirectory()-ed before the test block at the bottom).
if(CRYPTO_BUILD_TESTS)
    enable_testing()
endif()
option(GPUKIT_ENABLE_CUDA "Build gpukit CUDA driver" OFF)
option(GPUKIT_ENABLE_WGSL "Build gpukit WGSL driver" ${CRYPTO_ENABLE_WGSL})
add_subdirectory(gpukit)

# Top-level dispatcher (GPU control + version) lives next to the public header.
add_library(crypto STATIC c-abi/c_crypto.cpp)
target_include_directories(crypto
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/c-abi>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_compile_features(crypto PUBLIC cxx_std_20)
set_target_properties(crypto PROPERTIES POSITION_INDEPENDENT_CODE ON)
foreach(_alg ${CRYPTO_ALGS})
    target_link_libraries(crypto PUBLIC ${_alg})
endforeach()
add_library(kinet::crypto ALIAS crypto)

# Phase-1 kinet_crypto_* aliases dropped 2026-04-28 — call secp256k1_cpu /
# keccak_cpu directly. Brand-neutral C-ABI per LP-137.

# =============================================================================
# Tests (first-party implementations only; placeholders are not exercised)
# =============================================================================

if(CRYPTO_BUILD_TESTS)
    enable_testing()

    add_executable(keccak_test keccak/test/keccak_test.cpp)
    target_link_libraries(keccak_test PRIVATE keccak_cpu)
    add_test(NAME keccak_test COMMAND keccak_test)

    # poseidon (Goldilocks t=8) — KAT byte-equal to horizen-labs/poseidon2.
    add_executable(poseidon_goldilocks_test poseidon/test/poseidon_goldilocks_test.cpp)
    target_link_libraries(poseidon_goldilocks_test PRIVATE poseidon crypto)
    target_include_directories(poseidon_goldilocks_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/poseidon/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/c-abi
    )
    add_test(NAME poseidon_goldilocks_test COMMAND poseidon_goldilocks_test)

    add_executable(keccak_service_test keccak/test/keccak_service_test.cpp)
    target_link_libraries(keccak_service_test PRIVATE keccak_cpu)
    target_include_directories(keccak_service_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/keccak/cpp
    )
    add_test(NAME keccak_service_test COMMAND keccak_service_test)

    add_executable(secp256k1_test secp256k1/test/secp256k1_test.cpp)
    target_link_libraries(secp256k1_test PRIVATE secp256k1_cpu keccak_cpu)
    target_include_directories(secp256k1_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/cpp
    )
    add_test(NAME secp256k1_test COMMAND secp256k1_test)

    # secp256r1 (NIST P-256, RIP-7212 / EIP-7951): wired CPU verify,
    # FIPS 186-4 A.2.5 sample + EIP-7951 reference digest vectors.
    add_executable(secp256r1_test secp256r1/test/secp256r1_test.cpp)
    target_link_libraries(secp256r1_test PRIVATE secp256r1)
    target_include_directories(secp256r1_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/secp256r1/cpp
    )
    add_test(NAME secp256r1_test COMMAND secp256r1_test)

    add_executable(secp256k1_batch_inv_test secp256k1/test/secp256k1_batch_inv_test.cpp)
    target_link_libraries(secp256k1_batch_inv_test PRIVATE secp256k1_cpu keccak_cpu)
    target_include_directories(secp256k1_batch_inv_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/cpp
    )
    add_test(NAME secp256k1_batch_inv_test COMMAND secp256k1_batch_inv_test)

    add_executable(secp256k1_ecrecover_pipeline_test
        secp256k1/test/secp256k1_ecrecover_pipeline_test.cpp)
    target_link_libraries(secp256k1_ecrecover_pipeline_test
        PRIVATE secp256k1_cpu keccak_cpu)
    target_include_directories(secp256k1_ecrecover_pipeline_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/cpp
    )
    add_test(NAME secp256k1_ecrecover_pipeline_test
             COMMAND secp256k1_ecrecover_pipeline_test)

    # secp256k1 batch_inv CPU<->CUDA determinism. On non-CUDA hosts the
    # driver returns NOTIMPL and the test self-skips via CRYPTO_HAS_CUDA.
    if(CRYPTO_ENABLE_CUDA)
        add_executable(batch_inv_cuda_test
            secp256k1/test/batch_inv_cuda_test.cu)
        set_target_properties(batch_inv_cuda_test PROPERTIES
            CUDA_ARCHITECTURES "75"
        )
    else()
        set_source_files_properties(secp256k1/test/batch_inv_cuda_test.cu
            PROPERTIES LANGUAGE CXX)
        add_executable(batch_inv_cuda_test
            secp256k1/test/batch_inv_cuda_test.cu)
        target_compile_features(batch_inv_cuda_test PRIVATE cxx_std_20)
    endif()
    target_link_libraries(batch_inv_cuda_test PRIVATE
        secp256k1_cpu secp256k1_batch_inv_cuda)
    target_include_directories(batch_inv_cuda_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/cpp
    )
    add_test(NAME batch_inv_cuda_test COMMAND batch_inv_cuda_test)

    # secp256k1 batch_inv CPU<->WGSL determinism. Self-skips when
    # CRYPTO_HAS_WGSL / CRYPTO_SECP256K1_BATCH_INV_WGSL unset.
    add_executable(batch_inv_wgsl_test
        secp256k1/test/batch_inv_wgsl_test.cpp)
    target_compile_features(batch_inv_wgsl_test PRIVATE cxx_std_20)
    target_link_libraries(batch_inv_wgsl_test PRIVATE
        secp256k1_cpu secp256k1_batch_inv_wgsl)
    target_include_directories(batch_inv_wgsl_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/cpp
    )
    add_test(NAME batch_inv_wgsl_test COMMAND batch_inv_wgsl_test)

    add_executable(attestation_test attestation/test/attestation_test.cpp)
    target_link_libraries(attestation_test PRIVATE attestation_cpu keccak_cpu)
    target_include_directories(attestation_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/attestation/include
    )
    target_compile_definitions(attestation_test PRIVATE
        ATTESTATION_TESTDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/attestation/testdata"
    )
    add_test(NAME attestation_test COMMAND attestation_test)

    add_executable(composite_test attestation/test/composite_test.cpp)
    target_link_libraries(composite_test PRIVATE attestation_cpu keccak_cpu)
    target_include_directories(composite_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/attestation/include
    )
    add_test(NAME composite_test COMMAND composite_test)

    # SHA-256 (FIPS 180-4): wired CPU implementation, NIST test vectors.
    add_executable(sha256_test sha256/test/sha256_test.cpp)
    target_link_libraries(sha256_test PRIVATE sha256)
    add_test(NAME sha256_test COMMAND sha256_test)

    # SHA-256 CPU↔CUDA byte-equality (100/100 vectors covering all
    # padding edges). Stub returns 0 / "not available" on Apple/non-CUDA
    # hosts so the test still passes structurally.
    add_executable(sha256_cuda_test sha256/test/sha256_cuda_test.cpp)
    target_link_libraries(sha256_cuda_test PRIVATE sha256_cpu sha256_batch_cuda)
    target_include_directories(sha256_cuda_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/sha256/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/sha256/gpu/cuda
    )
    add_test(NAME sha256_cuda_test COMMAND sha256_cuda_test)

    # SHA-256 CPU↔WGSL byte-equality. Stub returns 0 / "not available"
    # when the wgpu-native runtime is missing.
    add_executable(sha256_wgpu_test sha256/test/sha256_wgpu_test.cpp)
    target_link_libraries(sha256_wgpu_test PRIVATE sha256_cpu sha256_batch_wgpu)
    target_include_directories(sha256_wgpu_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/sha256/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/sha256/gpu/wgsl
    )
    add_test(NAME sha256_wgpu_test COMMAND sha256_wgpu_test)

    # FROST batched pre-signing kernel: CPU canonical body byte-equal to
    # the CUDA host polyfill across 100 random batches and a deterministic
    # KAT (zero-seed). Covers M=10 signers x N=64 slots = 640 commitments
    # plus N=100 random shapes.
    add_executable(frost_presign_test frost/test/frost_presign_test.cpp)
    target_link_libraries(frost_presign_test PRIVATE frost_cpu frost_cuda)
    target_include_directories(frost_presign_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/frost/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/cpp
    )
    add_test(NAME frost_presign_test COMMAND frost_presign_test)

    # CGGMP21 batched pre-signing kernel: secp256k1 portion (R = k*G)
    # wired and byte-equal to the CUDA host polyfill across 100 random
    # batches. Paillier ciphertext + ZK proof are reserved bytes
    # (status=0xFF) until the 2048-bit Karatsuba modexp primitive lands;
    # the test asserts the wire layout is frozen.
    add_executable(cggmp21_presign_test cggmp21/test/cggmp21_presign_test.cpp)
    target_link_libraries(cggmp21_presign_test PRIVATE cggmp21_cpu cggmp21_cuda)
    target_include_directories(cggmp21_presign_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/cggmp21/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/cpp
    )
    add_test(NAME cggmp21_presign_test COMMAND cggmp21_presign_test)

    # Paillier 2048-bit KAT — keygen (1024-bit p,q via MR-40) + 8 encrypt/
    # decrypt round-trips + Π^enc accept + Π^enc reject (tampered K) +
    # pinned ciphertext-SHA cross-oracle. Exercises cggmp21/cpp/paillier.{cpp,
    # hpp} on the LP-163 Karatsuba modexp primitive. Runtime is keygen-bound
    # (~60–120 s on a single core); generous TIMEOUT below.
    add_executable(paillier_test cggmp21/test/paillier_test.cpp)
    target_link_libraries(paillier_test PRIVATE cggmp21_cpu modexp sha256_cpu)
    target_include_directories(paillier_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/cggmp21/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/sha256/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/modexp/cpp
    )
    add_test(NAME paillier_test COMMAND paillier_test)
    set_tests_properties(paillier_test PROPERTIES TIMEOUT 600)

    # RIPEMD-160 (Dobbertin et al. 1996): wired CPU implementation,
    # reference vectors from the original paper.
    add_executable(ripemd160_test ripemd160/test/ripemd160_test.cpp)
    target_link_libraries(ripemd160_test PRIVATE ripemd160)
    add_test(NAME ripemd160_test COMMAND ripemd160_test)

    # RIPEMD-160 CPU↔CUDA byte-equality (100/100 vectors covering all
    # padding edges). Stub returns 0 / "not available" on Apple/non-CUDA
    # hosts so the test still passes structurally.
    add_executable(ripemd160_cuda_test ripemd160/test/ripemd160_cuda_test.cpp)
    target_link_libraries(ripemd160_cuda_test PRIVATE
        ripemd160_cpu ripemd160_batch_cuda)
    target_include_directories(ripemd160_cuda_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/ripemd160/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ripemd160/gpu/cuda
    )
    add_test(NAME ripemd160_cuda_test COMMAND ripemd160_cuda_test)

    # RIPEMD-160 CPU↔WGSL byte-equality. Stub returns 0 / "not available"
    # when the wgpu-native runtime is missing.
    add_executable(ripemd160_wgpu_test ripemd160/test/ripemd160_wgpu_test.cpp)
    target_link_libraries(ripemd160_wgpu_test PRIVATE
        ripemd160_cpu ripemd160_batch_wgpu)
    target_include_directories(ripemd160_wgpu_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/ripemd160/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ripemd160/gpu/wgsl
    )
    add_test(NAME ripemd160_wgpu_test COMMAND ripemd160_wgpu_test)

    # BLAKE2b (RFC 7693): wired CPU implementation, RFC test vectors.
    add_executable(blake2b_test blake2b/test/blake2b_test.cpp)
    target_link_libraries(blake2b_test PRIVATE blake2b)
    add_test(NAME blake2b_test COMMAND blake2b_test)

    # bn254 (alt_bn128): EIP-196 G1Add/G1Mul + EIP-197 pairing-check KAT.
    add_executable(bn254_kat_test bn254/test/bn254_kat_test.cpp)
    target_link_libraries(bn254_kat_test PRIVATE bn254_cpu)
    add_test(NAME bn254_kat_test COMMAND bn254_kat_test)

    # bn254 GPU determinism harness: dispatches the same vectors through CUDA
    # and WebGPU drivers and asserts byte-equality with the CPU oracle.
    # Without a real device the drivers run the CPU oracle directly so the
    # wire format is still exercised end-to-end. Covers Fp_mul, G1Add, G1Mul,
    # SVDW, Fp2_mul, Fp12_mul, MillerIter (cyclo-sqr^100), pairing.
    add_executable(bn254_gpu_determinism_test
        bn254/test/bn254_gpu_determinism_test.cpp
        bn254/gpu/cuda/bn254_driver_cuda.cpp
        bn254/gpu/wgsl/bn254_driver_wgpu.cpp)
    target_link_libraries(bn254_gpu_determinism_test PRIVATE bn254_cpu)
    target_include_directories(bn254_gpu_determinism_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/bn254/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/bn254
        ${CMAKE_CURRENT_SOURCE_DIR}/bn254/gpu/cuda
        ${CMAKE_CURRENT_SOURCE_DIR}/bn254/gpu/wgsl)
    add_test(NAME bn254_gpu_determinism_test COMMAND bn254_gpu_determinism_test)

    # Codegen: bn254 GPU pairing constants emitted from CPU body.
    # Produces bn254_pairing_consts_{cuda.cuh,wgsl.wgslh} so CPU is the single
    # producer of Frobenius coefficients across both backends.
    add_executable(bn254_gen_pairing_constants
        bn254/test/tools/gen_pairing_constants.cpp)
    set(_bn_consts_cuda  ${CMAKE_CURRENT_SOURCE_DIR}/bn254/gpu/cuda/bn254_pairing_consts_cuda.cuh)
    set(_bn_consts_wgsl  ${CMAKE_CURRENT_BINARY_DIR}/bn254_pairing_consts_wgsl.wgslh)
    set(_bn_wgsl_kernel  ${CMAKE_CURRENT_SOURCE_DIR}/bn254/gpu/wgsl/bn254.wgsl)
    add_custom_command(
        OUTPUT ${_bn_consts_cuda} ${_bn_consts_wgsl}
        COMMAND bn254_gen_pairing_constants ${_bn_consts_cuda} ${_bn_consts_wgsl} ${_bn_wgsl_kernel}
        DEPENDS bn254_gen_pairing_constants ${_bn_wgsl_kernel}
        COMMENT "Regenerating bn254 pairing GPU constants from CPU body (and verifying inlined WGSL kernel constants)")
    add_custom_target(bn254_pairing_consts ALL
        DEPENDS ${_bn_consts_cuda} ${_bn_consts_wgsl})
    add_dependencies(bn254_gpu_determinism_test bn254_pairing_consts)

    # modexp (EIP-198) + evm256_{add,mul}mod KAT.
    add_executable(modexp_kat_test modexp/test/modexp_kat_test.cpp)
    target_link_libraries(modexp_kat_test PRIVATE modexp_cpu)
    add_test(NAME modexp_kat_test COMMAND modexp_kat_test)

    # modexp Karatsuba multiplication + RSA-class modexp parity test.
    # Cross-checks kmul against intx::umul (in-tree fixed-width oracle)
    # at 1024/2048/4096 bits, and asserts byte-identical modexp() vs
    # modexp_karatsuba() output on RSA-OAEP-style inputs (e=65537).
    add_executable(modexp_karatsuba_test modexp/test/modexp_karatsuba_test.cpp)
    target_link_libraries(modexp_karatsuba_test PRIVATE modexp_cpu intx::intx)
    target_include_directories(modexp_karatsuba_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/modexp/cpp)
    add_test(NAME modexp_karatsuba_test COMMAND modexp_karatsuba_test)

    # modexp Karatsuba CPU benchmark (mul-only timing): 1024/2048/4096 bits
    # schoolbook vs Karatsuba, plus end-to-end modexp_karatsuba vs modexp.
    # Off the default CTest suite (long-running); enable with `ctest -R bench`.
    add_executable(modexp_karatsuba_bench modexp/test/modexp_karatsuba_bench.cpp)
    target_link_libraries(modexp_karatsuba_bench PRIVATE modexp_cpu intx::intx)
    target_include_directories(modexp_karatsuba_bench PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/modexp/cpp)

    # modexp Karatsuba GPU determinism test. Compiles the CUDA kernel .cu as
    # plain C++ (host polyfill) and verifies byte-equality against the CPU
    # oracle at 16/32/64 limbs (1024/2048/4096 bit). When CRYPTO_ENABLE_CUDA
    # is ON the same .cu compiles as a real CUDA TU; the test runs against
    # the host-side polyfill body so the wire format is exercised end-to-end
    # without requiring an NVIDIA device in CI.
    add_executable(modexp_karatsuba_gpu_test
        modexp/test/modexp_karatsuba_gpu_test.cpp
        modexp/gpu/cuda/modexp_karatsuba.cu)
    set_source_files_properties(modexp/gpu/cuda/modexp_karatsuba.cu
        PROPERTIES LANGUAGE CXX)
    target_link_libraries(modexp_karatsuba_gpu_test PRIVATE modexp_cpu)
    target_include_directories(modexp_karatsuba_gpu_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/modexp/cpp)
    target_compile_features(modexp_karatsuba_gpu_test PRIVATE cxx_std_20)
    add_test(NAME modexp_karatsuba_gpu_test
             COMMAND modexp_karatsuba_gpu_test)

    # kzg (EIP-4844) GPU determinism: 100 deterministic blobs per op
    # (blob_to_kzg_commitment, compute_blob_kzg_proof, verify_kzg_proof) per
    # backend (cuda, wgpu). On hosts without a real device the driver runs
    # the CPU oracle path so the round-trip is exercised end-to-end and the
    # harness reports 100/100. On CI with hardware the same vectors flow
    # through the actual kernel and byte-equality is asserted. Reuses BLS12-
    # 381 G1+Fp arithmetic patterns from bls/gpu/{cuda,wgsl}/. Optional
    # EIP-4844 KAT block runs when CRYPTO_KZG_KAT_DIR is set.
    add_executable(kzg_gpu_determinism_test
        kzg/test/kzg_gpu_determinism_test.cpp
        kzg/gpu/cuda/kzg_driver_cuda.cpp
        kzg/gpu/wgsl/kzg_driver_wgpu.cpp)
    target_include_directories(kzg_gpu_determinism_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/kzg/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/kzg
        ${CMAKE_CURRENT_SOURCE_DIR}/bls/gpu/cuda
        ${CMAKE_CURRENT_SOURCE_DIR}/bls/gpu/wgsl)
    add_test(NAME kzg_gpu_determinism_test COMMAND kzg_gpu_determinism_test)

    # IPA (Bulletproofs over Banderwagon): 5 valid prover/verifier KAT
    # roundtrips at N=256 (in-domain + out-of-domain) byte-equal vs
    # kinet-labs/crypto/ipa Go reference, plus 3 negative-test rejections.
    add_executable(ipa_kat_test ipa/test/ipa_kat_test.cpp)
    target_link_libraries(ipa_kat_test PRIVATE ipa_cpu banderwagon_cpu)
    target_include_directories(ipa_kat_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/ipa/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ipa/test
        ${CMAKE_CURRENT_SOURCE_DIR}/banderwagon/cpp
    )
    add_test(NAME ipa_kat_test COMMAND ipa_kat_test)
    set_tests_properties(ipa_kat_test PROPERTIES TIMEOUT 120)

    # Ringtail (Ring-LWE threshold signature): 16 deterministic KAT vectors
    # byte-equal vs the Go oracle in kinet/threshold/cmd/ringtail_oracle.
    # Pins pk_sha256 + sig_sha256 + sig_first64 across (t, n) ∈
    # {1×1, 2×3, 2×2, 1×3, 2×5, 3×3, 3×5, 4×7, 5×9, 6×11, 7×11}. Source
    # vectors live in ringtail/test/ringtail_kat.h — regenerate by running
    # the Go oracle and redirecting stdout there:
    #   cd kinet/threshold/cmd/ringtail_oracle && \
    #     go run . > .../kinet-labs/crypto/ringtail/test/ringtail_kat.h
    add_executable(ringtail_kat_test ringtail/test/ringtail_kat_test.cpp)
    target_link_libraries(ringtail_kat_test PRIVATE ringtail_cpu sha256_cpu)
    target_include_directories(ringtail_kat_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/ringtail/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ringtail/test
        ${CMAKE_CURRENT_SOURCE_DIR}/sha256/cpp
    )
    add_test(NAME ringtail_kat_test COMMAND ringtail_kat_test)
    set_tests_properties(ringtail_kat_test PROPERTIES TIMEOUT 120)

    # banderwagon MSM doc-presence regression guard: asserts the variable-time
    # safety contract comment block at the top of multi_scalar_mul stays put.
    # Pure documentation check, no algorithmic dependency.
    add_executable(banderwagon_multiexp_doc_test
        banderwagon/test/multiexp_doc_test.cpp)
    target_compile_definitions(banderwagon_multiexp_doc_test PRIVATE
        MULTIEXP_HPP_PATH="${CMAKE_CURRENT_SOURCE_DIR}/banderwagon/cpp/multiexp.hpp"
    )
    add_test(NAME banderwagon_multiexp_doc_test COMMAND banderwagon_multiexp_doc_test)

    # Pedersen tree-reduce vector commit at the fixed Verkle width N = 256.
    # 1000 random commits per round, each compared byte-equal to the CPU
    # canonical lp::commit. Plus C-ABI null-pointer guards.
    add_executable(pedersen_tree_test pedersen/test/pedersen_tree_test.cpp)
    target_link_libraries(pedersen_tree_test PRIVATE pedersen_cpu pedersen)
    target_include_directories(pedersen_tree_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/pedersen/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/bn254/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/c-abi
    )
    add_test(NAME pedersen_tree_test COMMAND pedersen_tree_test)
    set_tests_properties(pedersen_tree_test PROPERTIES TIMEOUT 1800)

    # Per-backend determinism tests for the tree-reduce kernel. Each backend
    # registers unconditionally; the tests skip with success if their runtime
    # isn't available so CTest still surfaces the lane on every host.
    if(APPLE)
        add_executable(pedersen_tree_metal_determinism_test
            pedersen/test/pedersen_tree_metal_determinism_test.mm)
        target_link_libraries(pedersen_tree_metal_determinism_test PRIVATE
            pedersen_cpu pedersen pedersen_metal)
        target_include_directories(pedersen_tree_metal_determinism_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/pedersen/cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/bn254/cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/pedersen/gpu/metal
            ${CMAKE_CURRENT_SOURCE_DIR}/c-abi
        )
        set_target_properties(pedersen_tree_metal_determinism_test PROPERTIES
            COMPILE_FLAGS "-fobjc-arc")
        add_test(NAME pedersen_tree_metal_determinism_test
                 COMMAND pedersen_tree_metal_determinism_test)
        set_tests_properties(pedersen_tree_metal_determinism_test PROPERTIES
            TIMEOUT 1800)
    endif()

    add_executable(pedersen_tree_cuda_determinism_test
        pedersen/test/pedersen_tree_cuda_determinism_test.cpp)
    target_link_libraries(pedersen_tree_cuda_determinism_test PRIVATE
        pedersen_cpu pedersen pedersen_cuda)
    target_include_directories(pedersen_tree_cuda_determinism_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/pedersen/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/bn254/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/pedersen/gpu/cuda
        ${CMAKE_CURRENT_SOURCE_DIR}/c-abi
    )
    add_test(NAME pedersen_tree_cuda_determinism_test
             COMMAND pedersen_tree_cuda_determinism_test)
    set_tests_properties(pedersen_tree_cuda_determinism_test PROPERTIES
        TIMEOUT 1800)

    add_executable(pedersen_tree_wgpu_determinism_test
        pedersen/test/pedersen_tree_wgpu_determinism_test.cpp)
    target_link_libraries(pedersen_tree_wgpu_determinism_test PRIVATE
        pedersen_cpu pedersen pedersen_wgpu)
    target_include_directories(pedersen_tree_wgpu_determinism_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/pedersen/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/bn254/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/pedersen/gpu/wgsl
        ${CMAKE_CURRENT_SOURCE_DIR}/c-abi
    )
    add_test(NAME pedersen_tree_wgpu_determinism_test
             COMMAND pedersen_tree_wgpu_determinism_test)
    set_tests_properties(pedersen_tree_wgpu_determinism_test PROPERTIES
        TIMEOUT 1800)

    if(CRYPTO_ENABLE_METAL AND APPLE)
        find_program(XCRUN xcrun)
        if(XCRUN)
            # Pedersen metallib bundling BOTH the legacy two-stage kernel
            # (pedersen_pointmul + pedersen_reduce_add) and the tree-reduce
            # kernel (pedersen_tree_commit). Verkle width N = 256.
            set(_ped_legacy_metal ${CMAKE_CURRENT_SOURCE_DIR}/pedersen/gpu/metal/pedersen.metal)
            set(_ped_legacy_air   ${CMAKE_CURRENT_BINARY_DIR}/pedersen.air)
            set(_pedt_metal       ${CMAKE_CURRENT_SOURCE_DIR}/pedersen/gpu/metal/pedersen_tree.metal)
            set(_pedt_air         ${CMAKE_CURRENT_BINARY_DIR}/pedersen_tree.air)
            set(_pedt_lib         ${CMAKE_CURRENT_BINARY_DIR}/pedersen_tree.metallib)
            add_custom_command(
                OUTPUT ${_ped_legacy_air}
                COMMAND ${XCRUN} -sdk macosx metal -c ${_ped_legacy_metal} -o ${_ped_legacy_air}
                DEPENDS ${_ped_legacy_metal})
            add_custom_command(
                OUTPUT ${_pedt_air}
                COMMAND ${XCRUN} -sdk macosx metal -c ${_pedt_metal} -o ${_pedt_air}
                DEPENDS ${_pedt_metal})
            add_custom_command(
                OUTPUT ${_pedt_lib}
                COMMAND ${XCRUN} -sdk macosx metallib ${_ped_legacy_air} ${_pedt_air} -o ${_pedt_lib}
                DEPENDS ${_ped_legacy_air} ${_pedt_air})
            add_custom_target(pedersen_tree_metallib ALL DEPENDS ${_pedt_lib})
            add_dependencies(pedersen_tree_metal_determinism_test
                pedersen_tree_metallib)
            set_property(TEST pedersen_tree_metal_determinism_test PROPERTY
                ENVIRONMENT "CRYPTO_PEDERSEN_TREE_METALLIB=${_pedt_lib}")

            set(_secp_metal ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/gpu/metal/secp256k1.metal)
            set(_secp_air   ${CMAKE_CURRENT_BINARY_DIR}/secp256k1.air)
            set(_secp_lib   ${CMAKE_CURRENT_BINARY_DIR}/secp256k1.metallib)
            add_custom_command(
                OUTPUT ${_secp_air}
                COMMAND ${XCRUN} -sdk macosx metal -c ${_secp_metal} -o ${_secp_air}
                DEPENDS ${_secp_metal})
            add_custom_command(
                OUTPUT ${_secp_lib}
                COMMAND ${XCRUN} -sdk macosx metallib ${_secp_air} -o ${_secp_lib}
                DEPENDS ${_secp_air})
            add_custom_target(secp256k1_metallib ALL DEPENDS ${_secp_lib})

            add_executable(secp256k1_gpu_test secp256k1/test/secp256k1_gpu_test.cpp)
            target_link_libraries(secp256k1_gpu_test PRIVATE
                secp256k1_cpu secp256k1_metal keccak_cpu)
            target_include_directories(secp256k1_gpu_test PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/gpu/metal
            )
            add_dependencies(secp256k1_gpu_test secp256k1_metallib)
            add_test(NAME secp256k1_gpu_test COMMAND secp256k1_gpu_test)
            set_property(TEST secp256k1_gpu_test PROPERTY
                ENVIRONMENT "CRYPTO_SECP256K1_METALLIB=${_secp_lib}")

            # v0.63 Stage A: batch inversion metallib + CPU↔Metal byte-equality test.
            set(_binv_metal ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/gpu/metal/secp256k1_batch_inv.metal)
            set(_binv_air   ${CMAKE_CURRENT_BINARY_DIR}/secp256k1_batch_inv.air)
            set(_binv_lib   ${CMAKE_CURRENT_BINARY_DIR}/secp256k1_batch_inv.metallib)
            add_custom_command(
                OUTPUT ${_binv_air}
                COMMAND ${XCRUN} -sdk macosx metal -c ${_binv_metal} -o ${_binv_air}
                DEPENDS ${_binv_metal})
            add_custom_command(
                OUTPUT ${_binv_lib}
                COMMAND ${XCRUN} -sdk macosx metallib ${_binv_air} -o ${_binv_lib}
                DEPENDS ${_binv_air})
            add_custom_target(secp256k1_batch_inv_metallib ALL DEPENDS ${_binv_lib})

            add_executable(secp256k1_batch_inv_gpu_test
                secp256k1/test/secp256k1_batch_inv_gpu_test.cpp)
            target_link_libraries(secp256k1_batch_inv_gpu_test PRIVATE
                secp256k1_cpu secp256k1_batch_inv_metal)
            target_include_directories(secp256k1_batch_inv_gpu_test PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/cpp
            )
            add_dependencies(secp256k1_batch_inv_gpu_test secp256k1_batch_inv_metallib)
            add_test(NAME secp256k1_batch_inv_gpu_test COMMAND secp256k1_batch_inv_gpu_test)
            set_property(TEST secp256k1_batch_inv_gpu_test PROPERTY
                ENVIRONMENT "CRYPTO_SECP256K1_BATCH_INV_METALLIB=${_binv_lib}")

            # v0.63 keccak service: keccak_batch.metal + GPU vs CPU equality test.
            set(_kbatch_metal ${CMAKE_CURRENT_SOURCE_DIR}/keccak/gpu/metal/keccak_batch.metal)
            set(_kbatch_air   ${CMAKE_CURRENT_BINARY_DIR}/keccak_batch.air)
            set(_kbatch_lib   ${CMAKE_CURRENT_BINARY_DIR}/keccak_batch.metallib)
            add_custom_command(
                OUTPUT ${_kbatch_air}
                COMMAND ${XCRUN} -sdk macosx metal -c ${_kbatch_metal} -o ${_kbatch_air}
                DEPENDS ${_kbatch_metal})
            add_custom_command(
                OUTPUT ${_kbatch_lib}
                COMMAND ${XCRUN} -sdk macosx metallib ${_kbatch_air} -o ${_kbatch_lib}
                DEPENDS ${_kbatch_air})
            add_custom_target(keccak_batch_metallib ALL DEPENDS ${_kbatch_lib})

            # v0.64 sha256 batched: sha256_batch.metal + CPU↔Metal byte-equality test.
            set(_sha_metal ${CMAKE_CURRENT_SOURCE_DIR}/sha256/gpu/metal/sha256_batch.metal)
            set(_sha_air   ${CMAKE_CURRENT_BINARY_DIR}/sha256_batch.air)
            set(_sha_lib   ${CMAKE_CURRENT_BINARY_DIR}/sha256_batch.metallib)
            add_custom_command(
                OUTPUT ${_sha_air}
                COMMAND ${XCRUN} -sdk macosx metal -c ${_sha_metal} -o ${_sha_air}
                DEPENDS ${_sha_metal})
            add_custom_command(
                OUTPUT ${_sha_lib}
                COMMAND ${XCRUN} -sdk macosx metallib ${_sha_air} -o ${_sha_lib}
                DEPENDS ${_sha_air})
            add_custom_target(sha256_batch_metallib ALL DEPENDS ${_sha_lib})

            add_executable(sha256_metal_test sha256/test/sha256_metal_test.cpp)
            target_link_libraries(sha256_metal_test PRIVATE
                sha256_cpu sha256_batch_metal)
            target_include_directories(sha256_metal_test PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/sha256/cpp
            )
            add_dependencies(sha256_metal_test sha256_batch_metallib)
            add_test(NAME sha256_metal_test COMMAND sha256_metal_test)
            set_property(TEST sha256_metal_test PROPERTY
                ENVIRONMENT "CRYPTO_SHA256_METALLIB=${_sha_lib}")

            # v0.64 blake2b batched: blake2b_batch.metal + CPU↔Metal byte-equality.
            set(_b2b_metal ${CMAKE_CURRENT_SOURCE_DIR}/blake2b/gpu/metal/blake2b_batch.metal)
            set(_b2b_air   ${CMAKE_CURRENT_BINARY_DIR}/blake2b_batch.air)
            set(_b2b_lib   ${CMAKE_CURRENT_BINARY_DIR}/blake2b_batch.metallib)
            add_custom_command(
                OUTPUT ${_b2b_air}
                COMMAND ${XCRUN} -sdk macosx metal -c ${_b2b_metal} -o ${_b2b_air}
                DEPENDS ${_b2b_metal})
            add_custom_command(
                OUTPUT ${_b2b_lib}
                COMMAND ${XCRUN} -sdk macosx metallib ${_b2b_air} -o ${_b2b_lib}
                DEPENDS ${_b2b_air})
            add_custom_target(blake2b_batch_metallib ALL DEPENDS ${_b2b_lib})

            add_executable(blake2b_metal_test blake2b/test/blake2b_metal_test.cpp)
            target_link_libraries(blake2b_metal_test PRIVATE
                blake2b_cpu blake2b_batch_metal)
            target_include_directories(blake2b_metal_test PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/blake2b/cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/blake2b/c-abi
            )
            add_dependencies(blake2b_metal_test blake2b_batch_metallib)
            add_test(NAME blake2b_metal_test COMMAND blake2b_metal_test)
            set_property(TEST blake2b_metal_test PROPERTY
                ENVIRONMENT "CRYPTO_BLAKE2B_METALLIB=${_b2b_lib}")

            # blake3 batched: blake3_batch.metal + KAT byte-equality (no CPU
            # oracle indirection; asserts directly against BLAKE3 spec
            # test_vectors.json).
            set(_b3_metal ${CMAKE_CURRENT_SOURCE_DIR}/blake3/gpu/metal/blake3_batch.metal)
            set(_b3_air   ${CMAKE_CURRENT_BINARY_DIR}/blake3_batch.air)
            set(_b3_lib   ${CMAKE_CURRENT_BINARY_DIR}/blake3_batch.metallib)
            add_custom_command(
                OUTPUT ${_b3_air}
                COMMAND ${XCRUN} -sdk macosx metal -c ${_b3_metal} -o ${_b3_air}
                DEPENDS ${_b3_metal})
            add_custom_command(
                OUTPUT ${_b3_lib}
                COMMAND ${XCRUN} -sdk macosx metallib ${_b3_air} -o ${_b3_lib}
                DEPENDS ${_b3_air})
            add_custom_target(blake3_batch_metallib ALL DEPENDS ${_b3_lib})

            add_executable(blake3_metal_batch_test blake3/test/blake3_metal_test.cpp)
            target_link_libraries(blake3_metal_batch_test PRIVATE
                blake3_cpu blake3_batch_metal)
            target_include_directories(blake3_metal_batch_test PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/blake3/cpp
            )
            add_dependencies(blake3_metal_batch_test blake3_batch_metallib)
            add_test(NAME blake3_metal_batch_test COMMAND blake3_metal_batch_test)
            set_property(TEST blake3_metal_batch_test PROPERTY
                ENVIRONMENT
                "CRYPTO_BLAKE3_METALLIB=${_b3_lib};CRYPTO_BLAKE3_VECTORS=${CMAKE_CURRENT_SOURCE_DIR}/blake3/test/vectors/blake3_test_vectors.json")

            # poseidon2-bn254 batched: poseidon2_t2_batch.metal + KAT byte-equality.
            set(_p2_metal ${CMAKE_CURRENT_SOURCE_DIR}/poseidon/gpu/metal/poseidon2_t2_batch.metal)
            set(_p2_air   ${CMAKE_CURRENT_BINARY_DIR}/poseidon2_t2_batch.air)
            set(_p2_lib   ${CMAKE_CURRENT_BINARY_DIR}/poseidon2_t2_batch.metallib)
            add_custom_command(
                OUTPUT ${_p2_air}
                COMMAND ${XCRUN} -sdk macosx metal -c ${_p2_metal} -o ${_p2_air}
                DEPENDS ${_p2_metal})
            add_custom_command(
                OUTPUT ${_p2_lib}
                COMMAND ${XCRUN} -sdk macosx metallib ${_p2_air} -o ${_p2_lib}
                DEPENDS ${_p2_air})
            add_custom_target(poseidon2_t2_batch_metallib ALL DEPENDS ${_p2_lib})

            add_executable(poseidon_metal_batch_test poseidon/test/poseidon_metal_test.cpp)
            target_link_libraries(poseidon_metal_batch_test PRIVATE
                poseidon_cpu poseidon2_t2_batch_metal)
            target_include_directories(poseidon_metal_batch_test PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/poseidon/cpp
            )
            add_dependencies(poseidon_metal_batch_test poseidon2_t2_batch_metallib)
            add_test(NAME poseidon_metal_batch_test COMMAND poseidon_metal_batch_test)
            set_property(TEST poseidon_metal_batch_test PROPERTY
                ENVIRONMENT
                "CRYPTO_POSEIDON_METALLIB=${_p2_lib};CRYPTO_POSEIDON_VECTORS=${CMAKE_CURRENT_SOURCE_DIR}/poseidon/test/vectors/poseidon2_t2_kat.json")

            # v0.64 ripemd160 batched: ripemd160_batch.metal + CPU↔Metal byte-equality.
            set(_rmd_metal ${CMAKE_CURRENT_SOURCE_DIR}/ripemd160/gpu/metal/ripemd160_batch.metal)
            set(_rmd_air   ${CMAKE_CURRENT_BINARY_DIR}/ripemd160_batch.air)
            set(_rmd_lib   ${CMAKE_CURRENT_BINARY_DIR}/ripemd160_batch.metallib)
            add_custom_command(
                OUTPUT ${_rmd_air}
                COMMAND ${XCRUN} -sdk macosx metal -c ${_rmd_metal} -o ${_rmd_air}
                DEPENDS ${_rmd_metal})
            add_custom_command(
                OUTPUT ${_rmd_lib}
                COMMAND ${XCRUN} -sdk macosx metallib ${_rmd_air} -o ${_rmd_lib}
                DEPENDS ${_rmd_air})
            add_custom_target(ripemd160_batch_metallib ALL DEPENDS ${_rmd_lib})

            add_executable(ripemd160_metal_test ripemd160/test/ripemd160_metal_test.cpp)
            target_link_libraries(ripemd160_metal_test PRIVATE
                ripemd160_cpu ripemd160_batch_metal)
            target_include_directories(ripemd160_metal_test PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/ripemd160/cpp
            )
            add_dependencies(ripemd160_metal_test ripemd160_batch_metallib)
            add_test(NAME ripemd160_metal_test COMMAND ripemd160_metal_test)
            set_property(TEST ripemd160_metal_test PROPERTY
                ENVIRONMENT "CRYPTO_RIPEMD160_METALLIB=${_rmd_lib}")

            # Banderwagon Metal kernel. The .metal kernel #include's
            # banderwagon_const.metalh emitted by the unified codegen
            # (banderwagon_gen_gpu_constants -- registered below); we stage
            # the .metal next to the header for the metal compiler.
            set(_bw_metal_src ${CMAKE_CURRENT_SOURCE_DIR}/banderwagon/gpu/metal/banderwagon.metal)
            set(_bw_metal_staged ${CMAKE_CURRENT_BINARY_DIR}/banderwagon.metal)
            set(_bw_air ${CMAKE_CURRENT_BINARY_DIR}/banderwagon.air)
            set(_bw_lib ${CMAKE_CURRENT_BINARY_DIR}/banderwagon.metallib)

            add_custom_command(
                OUTPUT ${_bw_metal_staged}
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${_bw_metal_src} ${_bw_metal_staged}
                DEPENDS ${_bw_metal_src})

            add_custom_command(
                OUTPUT ${_bw_air}
                COMMAND ${XCRUN} -sdk macosx metal -c ${_bw_metal_staged} -o ${_bw_air}
                DEPENDS ${_bw_metal_staged}
                        ${CMAKE_CURRENT_BINARY_DIR}/banderwagon_const.metalh)
            add_custom_command(
                OUTPUT ${_bw_lib}
                COMMAND ${XCRUN} -sdk macosx metallib ${_bw_air} -o ${_bw_lib}
                DEPENDS ${_bw_air})
            add_custom_target(banderwagon_metallib ALL DEPENDS ${_bw_lib})

            add_executable(banderwagon_metal_determinism_test
                banderwagon/test/banderwagon_metal_determinism_test.mm)
            target_link_libraries(banderwagon_metal_determinism_test PRIVATE
                banderwagon_cpu banderwagon_metal)
            target_include_directories(banderwagon_metal_determinism_test PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/banderwagon/cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/banderwagon/gpu/metal)
            set_target_properties(banderwagon_metal_determinism_test PROPERTIES
                COMPILE_FLAGS "-fobjc-arc")
            target_link_libraries(banderwagon_metal_determinism_test PRIVATE
                "-framework Metal" "-framework Foundation")
            add_dependencies(banderwagon_metal_determinism_test banderwagon_metallib)
            add_test(NAME banderwagon_metal_determinism_test
                COMMAND banderwagon_metal_determinism_test)
            set_property(TEST banderwagon_metal_determinism_test PROPERTY
                ENVIRONMENT "CRYPTO_BANDERWAGON_METALLIB=${_bw_lib}")
        endif()
    endif()

    # =========================================================================
    # Banderwagon unified GPU constant codegen. Same internal accessors as the
    # CPU body -- one tool emits .metalh, .cuh, .wgslh from a single source so
    # drift between CPU and any GPU backend is structurally impossible.
    # =========================================================================
    add_executable(banderwagon_gen_gpu_constants
        banderwagon/test/tools/gen_gpu_constants.cpp)
    target_link_libraries(banderwagon_gen_gpu_constants PRIVATE banderwagon_cpu)
    target_include_directories(banderwagon_gen_gpu_constants PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/banderwagon/cpp)

    set(_bw_const_metalh ${CMAKE_CURRENT_BINARY_DIR}/banderwagon_const.metalh)
    set(_bw_const_cuh    ${CMAKE_CURRENT_BINARY_DIR}/banderwagon_const.cuh)
    set(_bw_const_wgslh  ${CMAKE_CURRENT_BINARY_DIR}/banderwagon_const.wgslh)
    add_custom_command(
        OUTPUT ${_bw_const_metalh} ${_bw_const_cuh} ${_bw_const_wgslh}
        COMMAND banderwagon_gen_gpu_constants
            ${_bw_const_metalh} ${_bw_const_cuh} ${_bw_const_wgslh}
        DEPENDS banderwagon_gen_gpu_constants
        COMMENT "Generating Banderwagon GPU constant headers (Metal/CUDA/WGSL)")
    add_custom_target(banderwagon_gpu_constants ALL
        DEPENDS ${_bw_const_metalh} ${_bw_const_cuh} ${_bw_const_wgslh})

    # =========================================================================
    # Banderwagon CUDA backend. nvcc-compiled when CRYPTO_ENABLE_CUDA=ON;
    # otherwise the same .cu file compiles as plain C++ via the host polyfill.
    # Either path runs the identical kernel body and yields byte-equal output
    # to the CPU oracle by construction.
    # =========================================================================
    if(CRYPTO_ENABLE_CUDA)
        add_library(banderwagon_cuda STATIC
            banderwagon/gpu/cuda/banderwagon.cu)
        set_source_files_properties(banderwagon/gpu/cuda/banderwagon.cu
            PROPERTIES LANGUAGE CUDA)
        set_target_properties(banderwagon_cuda PROPERTIES
            POSITION_INDEPENDENT_CODE ON
            CUDA_SEPARABLE_COMPILATION ON)
    else()
        add_library(banderwagon_cuda STATIC
            banderwagon/gpu/cuda/banderwagon.cu)
        set_source_files_properties(banderwagon/gpu/cuda/banderwagon.cu
            PROPERTIES LANGUAGE CXX)
        target_compile_features(banderwagon_cuda PUBLIC cxx_std_20)
        set_target_properties(banderwagon_cuda PROPERTIES
            POSITION_INDEPENDENT_CODE ON)
    endif()
    target_include_directories(banderwagon_cuda
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/banderwagon/gpu/cuda>
        PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)
    add_dependencies(banderwagon_cuda banderwagon_gpu_constants)
    add_library(kinet::banderwagon_cuda ALIAS banderwagon_cuda)

    add_executable(banderwagon_cuda_determinism_test
        banderwagon/test/banderwagon_cuda_determinism_test.cpp)
    target_link_libraries(banderwagon_cuda_determinism_test
        PRIVATE banderwagon_cpu banderwagon_cuda)
    target_include_directories(banderwagon_cuda_determinism_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/banderwagon/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/banderwagon/gpu/cuda)
    add_test(NAME banderwagon_cuda_determinism_test
        COMMAND banderwagon_cuda_determinism_test)

    # =========================================================================
    # Banderwagon WGSL backend. Host polyfill mirrors the .wgsl kernel byte-
    # for-byte using only u32 ops (WGSL has no native u64). Byte-equal to the
    # CPU oracle by construction; no wgpu runtime needed in CI.
    # =========================================================================
    add_library(banderwagon_wgsl STATIC
        banderwagon/gpu/wgsl/banderwagon_driver.cpp)
    target_include_directories(banderwagon_wgsl
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/banderwagon/gpu/wgsl>
        PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)
    target_compile_features(banderwagon_wgsl PUBLIC cxx_std_20)
    set_target_properties(banderwagon_wgsl PROPERTIES POSITION_INDEPENDENT_CODE ON)
    add_dependencies(banderwagon_wgsl banderwagon_gpu_constants)
    add_library(kinet::banderwagon_wgsl ALIAS banderwagon_wgsl)

    add_executable(banderwagon_wgsl_determinism_test
        banderwagon/test/banderwagon_wgsl_determinism_test.cpp)
    target_link_libraries(banderwagon_wgsl_determinism_test
        PRIVATE banderwagon_cpu banderwagon_wgsl)
    target_include_directories(banderwagon_wgsl_determinism_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/banderwagon/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/banderwagon/gpu/wgsl)
    add_test(NAME banderwagon_wgsl_determinism_test
        COMMAND banderwagon_wgsl_determinism_test)

    # =========================================================================
    # NTT large-N (six-step) round-trip + cross-backend byte-equality.
    # Covers N in {2^17, 2^18, 2^19, 2^20} for both Cyclone-FFT prime
    # (Q = 119*2^23 + 1) and TFHE q = 2^64. CPU oracle plus CUDA/Metal/WGSL
    # drivers (currently CPU-fallback on hosts without devices).
    # =========================================================================
    add_executable(ntt_large_test ntt/test/ntt_large_test.cpp)
    target_link_libraries(ntt_large_test PRIVATE
        ntt_cpu
        ntt_large_gpu_cuda
        ntt_large_gpu_metal
        ntt_large_gpu_wgsl)
    target_include_directories(ntt_large_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/ntt/cpp)
    add_test(NAME ntt_large_test COMMAND ntt_large_test)
    set_tests_properties(ntt_large_test PROPERTIES TIMEOUT 600)

    # =========================================================================
    # Per-algorithm KAT tests (LP-178 audit a90c7a8a52ef12c96).
    # One registered ctest entry per algorithm exercising the C-ABI surface
    # with at least one Known-Answer Test vector. Source upstream wherever the
    # spec is published (RFC/FIPS/EIP); self-generated for poly_mul (NTT) and
    # ringtail (vs Go reference).
    # =========================================================================

    # aead -- ChaCha20-Poly1305 RFC 8439 §2.8.2 + AES-256-GCM NIST CAVP
    # (gcmEncryptExtIV256.rsp Keylen=256 IVlen=96). Calls aead_chacha20poly1305_*
    # and aead_aes_256_gcm_* C-ABI directly. Links umbrella `aead` for the shim.
    add_executable(aead_kat_test aead/test/aead_kat_test.cpp)
    target_link_libraries(aead_kat_test PRIVATE aead)
    target_include_directories(aead_kat_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/aead/cpp)
    add_test(NAME aead_kat_test COMMAND aead_kat_test)

    # bls -- BLS12-381 IRTF (POP DST) determinism via bls_keygen + bls_sk_to_pk
    # + bls_sign + bls_verify C-ABI. Oracle body links blst (test-only, never
    # in production archives per LP-137); registered only when blst is on disk.
    # bls_stage1_blst is an IMPORTED target declared in bls/CMakeLists.txt --
    # not visible at top-level. Link the libblst.a path directly instead, the
    # same way the oracle target's transitive linkage already pulls it in.
    set(_BLST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../cevm/build/deps/src/blst/libblst.a")
    if(TARGET bls_signature_oracle AND EXISTS "${_BLST_PATH}")
        add_executable(bls_kat_test bls/test/bls_kat_test.cpp)
        target_link_libraries(bls_kat_test PRIVATE bls bls_signature_oracle "${_BLST_PATH}")
        target_include_directories(bls_kat_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/c-abi
            ${CMAKE_CURRENT_SOURCE_DIR}/bls/c-abi
            ${CMAKE_CURRENT_SOURCE_DIR}/bls/cpp)
        add_test(NAME bls_kat_test COMMAND bls_kat_test)
    endif()

    # ed25519 -- RFC 8032 §7.1 KAT (8 vectors) + 10 random-seed roundtrips.
    add_executable(ed25519_kat_test ed25519/test/ed25519_kat_test.cpp)
    target_link_libraries(ed25519_kat_test PRIVATE ed25519_cpu)
    target_include_directories(ed25519_kat_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/ed25519/cpp)
    add_test(NAME ed25519_kat_test COMMAND ed25519_kat_test)

    # evm256 -- EIP-198/EIP-7951 ADDMOD/MULMOD KAT (12 + 12 vectors via
    # evm256_addmod / evm256_mulmod C-ABI).
    add_executable(evm256_test evm256/test/evm256_test.cpp)
    target_link_libraries(evm256_test PRIVATE evm256_cpu)
    target_include_directories(evm256_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/evm256/cpp)
    add_test(NAME evm256_test COMMAND evm256_test)

    # lamport -- C-ABI dispatch test (lamport_keygen/sign/verify roundtrip with
    # tamper rejection + null-arg validation). Pins the C-ABI surface.
    add_executable(lamport_kat_test lamport/test/lamport_cabi_test.cpp)
    target_link_libraries(lamport_kat_test PRIVATE lamport)
    target_include_directories(lamport_kat_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/lamport/cpp)
    add_test(NAME lamport_kat_test COMMAND lamport_kat_test)

    # mldsa -- FIPS 204 NIST KAT (3 byte-equal nistkat-sha256 + 30 deterministic
    # DRBG rounds). Uses mldsa_{keygen,sign,verify} C-ABI under chained
    # AES-256-CTR DRBG seeded with entropy_input[48] = 0..47.
    add_executable(mldsa_kat_test mldsa/test/mldsa_kat_test.cpp)
    target_link_libraries(mldsa_kat_test PRIVATE mldsa_cpu pqclean_kat)
    target_include_directories(mldsa_kat_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/mldsa/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/pqclean_kat
        ${KINETCPP_PQCLEAN_SOURCE_DIR}/crypto_sign)
    add_test(NAME mldsa_kat_test COMMAND mldsa_kat_test)
    set_tests_properties(mldsa_kat_test PROPERTIES TIMEOUT 300)

    # mlkem -- FIPS 203 NIST KAT (3 byte-equal nistkat-sha256 + 30 DRBG rounds).
    add_executable(mlkem_kat_test mlkem/test/mlkem_kat_test.cpp)
    target_link_libraries(mlkem_kat_test PRIVATE mlkem_cpu pqclean_kat)
    target_include_directories(mlkem_kat_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/mlkem/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/pqclean_kat
        ${KINETCPP_PQCLEAN_SOURCE_DIR}/crypto_kem)
    add_test(NAME mlkem_kat_test COMMAND mlkem_kat_test)
    set_tests_properties(mlkem_kat_test PROPERTIES TIMEOUT 300)

    # poly_mul -- self-generated NTT KAT (pinned (n, seedA, seedB, sum, first,
    # last) tuples from kinet/crypto/poly_mul Go reference; lockstep changes).
    # Calls C-ABI int poly_mul(...) directly via umbrella `poly_mul` lib.
    add_executable(poly_mul_test poly_mul/test/poly_mul_test.cpp)
    target_link_libraries(poly_mul_test PRIVATE poly_mul ntt_cpu)
    target_include_directories(poly_mul_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/poly_mul/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ntt/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/c-abi)
    add_test(NAME poly_mul_test COMMAND poly_mul_test)

    # ringtail -- already registered above (line 540) via ringtail_kat_test
    # cross-oracle vs kinet/threshold/cmd/ringtail_oracle Go reference. Skip.

    # slhdsa -- FIPS 205 NIST KAT (6 byte-equal nistkat-sha256 + 60 DRBG rounds
    # over the six 'f' parameter sets). SLH-DSA-256f sign() takes multi-second
    # on M1; long timeout below.
    add_executable(slhdsa_kat_test slhdsa/test/slhdsa_kat_test.cpp)
    target_link_libraries(slhdsa_kat_test PRIVATE slhdsa_cpu pqclean_kat)
    target_include_directories(slhdsa_kat_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/slhdsa/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/pqclean_kat
        ${KINETCPP_PQCLEAN_SOURCE_DIR}/crypto_sign)
    add_test(NAME slhdsa_kat_test COMMAND slhdsa_kat_test)
    set_tests_properties(slhdsa_kat_test PROPERTIES TIMEOUT 1800)

    # sr25519 -- C-ABI scaffold contract. First-party body has not landed
    # (per audit ac17eea51acbd0ab3); both sr25519_sign and sr25519_verify
    # return CRYPTO_ERR_NOTIMPL after argument validation. Test asserts that
    # contract and is labeled DISABLED at registration so it does not run in
    # the default ctest pass and so it does not falsely appear as a 0-vector
    # test.
    add_executable(sr25519_test sr25519/test/sr25519_test.cpp)
    target_link_libraries(sr25519_test PRIVATE sr25519)
    add_test(NAME sr25519_test COMMAND sr25519_test)
    set_tests_properties(sr25519_test PROPERTIES
        LABELS DISABLED
        DISABLED TRUE)

    # verkle -- input-validation contract for verify_batch (10 negative + 12
    # well-formed-but-NOTIMPL). Body returns kStatusNotImplemented until the
    # IPA + Banderwagon backends land; this test pins the C++ surface that
    # c_verkle.cpp routes the C-ABI verkle_verify through.
    add_executable(verkle_test verkle/test/verkle_test.cpp)
    target_link_libraries(verkle_test PRIVATE verkle_cpu)
    target_include_directories(verkle_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/verkle/cpp)
    add_test(NAME verkle_test COMMAND verkle_test)
endif()

message(STATUS "=================================================")
message(STATUS "kinet-labs/crypto v${PROJECT_VERSION}")
message(STATUS "  Algorithms:  ${CRYPTO_ALGS}")
message(STATUS "  CUDA:        ${CRYPTO_ENABLE_CUDA}")
message(STATUS "  Metal:       ${CRYPTO_ENABLE_METAL}")
message(STATUS "  WGSL:        ${CRYPTO_ENABLE_WGSL}")
message(STATUS "  Tests:       ${CRYPTO_BUILD_TESTS}")
message(STATUS "=================================================")

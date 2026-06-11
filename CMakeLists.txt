cmake_minimum_required(VERSION 3.20)
project(kinet_crypto VERSION 1.0.0 LANGUAGES C CXX)

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
#   * No stubs in production paths -- placeholders return KINET_ERR_NOTIMPL and
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

option(KINET_CRYPTO_ENABLE_CUDA  "Build CUDA drivers"  OFF)
option(KINET_CRYPTO_ENABLE_METAL "Build Metal drivers" OFF)
option(KINET_CRYPTO_ENABLE_WGSL  "Build WGSL drivers"  OFF)
option(KINET_CRYPTO_BUILD_TESTS  "Build crypto tests"  ON)

if(APPLE)
    set(CRYPTO_ENABLE_METAL ON CACHE BOOL "Build Metal drivers" FORCE)
endif()

if(CRYPTO_ENABLE_CUDA)
    enable_language(CUDA)
    add_compile_definitions(CRYPTO_HAS_CUDA=1)
endif()
if(CRYPTO_ENABLE_METAL)
    enable_language(OBJCXX)
    add_compile_definitions(CRYPTO_HAS_METAL=1)
endif()
if(CRYPTO_ENABLE_WGSL)
    add_compile_definitions(CRYPTO_HAS_WGSL=1)
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
if(KINET_CRYPTO_BUILD_TESTS)
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

# Backwards-compatible aliases for the Phase-1 target names. Other Phase-1
# agents already build against kinet_crypto_secp256k1 / kinet_crypto_keccak.
add_library(kinet_crypto_secp256k1 ALIAS secp256k1_cpu)
add_library(kinet_crypto_keccak ALIAS keccak_cpu)

# =============================================================================
# Tests (first-party implementations only; placeholders are not exercised)
# =============================================================================

if(CRYPTO_BUILD_TESTS)
    enable_testing()

    add_executable(keccak_test keccak/test/keccak_test.cpp)
    target_link_libraries(keccak_test PRIVATE keccak_cpu)
    add_test(NAME keccak_test COMMAND keccak_test)

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

    add_executable(attestation_test attestation/test/attestation_test.cpp)
    target_link_libraries(attestation_test PRIVATE attestation_cpu keccak_cpu)
    target_include_directories(attestation_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/attestation/include
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

    # modexp (EIP-198) + evm256_{add,mul}mod KAT.
    add_executable(modexp_kat_test modexp/test/modexp_kat_test.cpp)
    target_link_libraries(modexp_kat_test PRIVATE modexp_cpu)
    add_test(NAME modexp_kat_test COMMAND modexp_kat_test)

    if(KINET_CRYPTO_ENABLE_METAL AND APPLE)
        find_program(XCRUN xcrun)
        if(XCRUN)
            set(_secp_metal ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/gpu/metal/secp256k1.metal)
            set(_secp_air   ${CMAKE_CURRENT_BINARY_DIR}/secp256k1.air)
            set(_secp_lib   ${CMAKE_CURRENT_BINARY_DIR}/kinet_crypto_secp256k1.metallib)
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
            set(_binv_lib   ${CMAKE_CURRENT_BINARY_DIR}/kinet_crypto_secp256k1_batch_inv.metallib)
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
            set(_kbatch_lib   ${CMAKE_CURRENT_BINARY_DIR}/kinet_crypto_keccak_batch.metallib)
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
            set(_sha_lib   ${CMAKE_CURRENT_BINARY_DIR}/kinet_crypto_sha256_batch.metallib)
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
            set(_b2b_lib   ${CMAKE_CURRENT_BINARY_DIR}/kinet_crypto_blake2b_batch.metallib)
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
            set(_b3_lib   ${CMAKE_CURRENT_BINARY_DIR}/kinet_crypto_blake3_batch.metallib)
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
                "KINET_CRYPTO_BLAKE3_METALLIB=${_b3_lib};KINET_CRYPTO_BLAKE3_VECTORS=${CMAKE_CURRENT_SOURCE_DIR}/blake3/test/vectors/blake3_test_vectors.json")

            # poseidon2-bn254 batched: poseidon2_t2_batch.metal + KAT byte-equality.
            set(_p2_metal ${CMAKE_CURRENT_SOURCE_DIR}/poseidon/gpu/metal/poseidon2_t2_batch.metal)
            set(_p2_air   ${CMAKE_CURRENT_BINARY_DIR}/poseidon2_t2_batch.air)
            set(_p2_lib   ${CMAKE_CURRENT_BINARY_DIR}/kinet_crypto_poseidon2_t2_batch.metallib)
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
                "KINET_CRYPTO_POSEIDON_METALLIB=${_p2_lib};KINET_CRYPTO_POSEIDON_VECTORS=${CMAKE_CURRENT_SOURCE_DIR}/poseidon/test/vectors/poseidon2_t2_kat.json")

            # v0.64 ripemd160 batched: ripemd160_batch.metal + CPU↔Metal byte-equality.
            set(_rmd_metal ${CMAKE_CURRENT_SOURCE_DIR}/ripemd160/gpu/metal/ripemd160_batch.metal)
            set(_rmd_air   ${CMAKE_CURRENT_BINARY_DIR}/ripemd160_batch.air)
            set(_rmd_lib   ${CMAKE_CURRENT_BINARY_DIR}/kinet_crypto_ripemd160_batch.metallib)
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
                ENVIRONMENT "KINET_CRYPTO_RIPEMD160_METALLIB=${_rmd_lib}")

            # v0.65 pedersen vector commitment: pedersen.metal + Go-oracle KAT
            # determinism test (M=8, N=256, 100 random rounds, byte-equal vs
            # the Go canonical at github.com/kinet-labs/crypto/pedersen).
            set(_ped_metal ${CMAKE_CURRENT_SOURCE_DIR}/pedersen/gpu/metal/pedersen.metal)
            set(_ped_air   ${CMAKE_CURRENT_BINARY_DIR}/pedersen.air)
            set(_ped_lib   ${CMAKE_CURRENT_BINARY_DIR}/kinet_crypto_pedersen.metallib)
            add_custom_command(
                OUTPUT ${_ped_air}
                COMMAND ${XCRUN} -sdk macosx metal -c ${_ped_metal} -o ${_ped_air}
                DEPENDS ${_ped_metal})
            add_custom_command(
                OUTPUT ${_ped_lib}
                COMMAND ${XCRUN} -sdk macosx metallib ${_ped_air} -o ${_ped_lib}
                DEPENDS ${_ped_air})
            add_custom_target(pedersen_metallib ALL DEPENDS ${_ped_lib})

            # Generate the deterministic KAT fixture via the Go reference at
            # pedersen/test/tools/metal_kat/main.go.  The test self-skips when
            # KINET_CRYPTO_PEDERSEN_KAT is unset, so hosts without Go on PATH
            # still build the test.
            find_program(GO_EXECUTABLE NAMES go)
            set(_ped_kat ${CMAKE_CURRENT_BINARY_DIR}/pedersen_metal.kat)
            if(GO_EXECUTABLE)
                add_custom_command(
                    OUTPUT ${_ped_kat}
                    COMMAND ${GO_EXECUTABLE} run .
                        -out ${_ped_kat}
                    WORKING_DIRECTORY
                        ${CMAKE_CURRENT_SOURCE_DIR}/pedersen/test/tools/metal_kat
                    DEPENDS
                        ${CMAKE_CURRENT_SOURCE_DIR}/pedersen/test/tools/metal_kat/main.go
                    COMMENT "Generating Pedersen Metal KAT fixture")
                add_custom_target(pedersen_metal_kat ALL DEPENDS ${_ped_kat})
            endif()

            add_executable(pedersen_metal_determinism_test
                pedersen/test/pedersen_metal_determinism_test.mm)
            set_target_properties(pedersen_metal_determinism_test PROPERTIES
                COMPILE_FLAGS "-fobjc-arc")
            target_link_libraries(pedersen_metal_determinism_test PRIVATE
                pedersen_metal)
            target_include_directories(pedersen_metal_determinism_test PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/pedersen/gpu/metal
            )
            add_dependencies(pedersen_metal_determinism_test pedersen_metallib)
            if(GO_EXECUTABLE)
                add_dependencies(pedersen_metal_determinism_test pedersen_metal_kat)
                add_test(NAME pedersen_metal_determinism_test
                         COMMAND pedersen_metal_determinism_test)
                set_property(TEST pedersen_metal_determinism_test PROPERTY
                    ENVIRONMENT
                    "KINET_CRYPTO_PEDERSEN_METALLIB=${_ped_lib};KINET_CRYPTO_PEDERSEN_KAT=${_ped_kat}")
            else()
                add_test(NAME pedersen_metal_determinism_test
                         COMMAND pedersen_metal_determinism_test)
                set_property(TEST pedersen_metal_determinism_test PROPERTY
                    ENVIRONMENT "KINET_CRYPTO_PEDERSEN_METALLIB=${_ped_lib}")
            endif()
        endif()
    endif()

    # v0.66 pedersen CUDA: byte-equal CPU-oracle determinism test (skipped on
    # hosts without a CUDA runtime).  Reuses the Go-generated KAT fixture.
    add_executable(pedersen_cuda_determinism_test
        pedersen/test/pedersen_cuda_determinism_test.cpp)
    target_link_libraries(pedersen_cuda_determinism_test PRIVATE pedersen_cuda)
    target_include_directories(pedersen_cuda_determinism_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/pedersen/gpu/cuda)
    if(KINET_CRYPTO_ENABLE_METAL AND APPLE AND GO_EXECUTABLE)
        add_dependencies(pedersen_cuda_determinism_test pedersen_metal_kat)
        add_test(NAME pedersen_cuda_determinism_test
                 COMMAND pedersen_cuda_determinism_test)
        set_property(TEST pedersen_cuda_determinism_test PROPERTY
            ENVIRONMENT "KINET_CRYPTO_PEDERSEN_KAT=${_ped_kat}")
    else()
        add_test(NAME pedersen_cuda_determinism_test
                 COMMAND pedersen_cuda_determinism_test)
    endif()

    # v0.66 pedersen WebGPU/WGSL: byte-equal CPU-oracle determinism test
    # (skipped on hosts without a wgpu runtime).
    add_executable(pedersen_wgpu_determinism_test
        pedersen/test/pedersen_wgpu_determinism_test.cpp)
    target_link_libraries(pedersen_wgpu_determinism_test PRIVATE pedersen_wgpu)
    target_include_directories(pedersen_wgpu_determinism_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/pedersen/gpu/wgsl)
    if(KINET_CRYPTO_ENABLE_METAL AND APPLE AND GO_EXECUTABLE)
        add_dependencies(pedersen_wgpu_determinism_test pedersen_metal_kat)
        add_test(NAME pedersen_wgpu_determinism_test
                 COMMAND pedersen_wgpu_determinism_test)
        set_property(TEST pedersen_wgpu_determinism_test PROPERTY
            ENVIRONMENT "KINET_CRYPTO_PEDERSEN_KAT=${_ped_kat}")
    else()
        add_test(NAME pedersen_wgpu_determinism_test
                 COMMAND pedersen_wgpu_determinism_test)
    endif()
endif()

message(STATUS "=================================================")
message(STATUS "kinet-labs/crypto v${PROJECT_VERSION}")
message(STATUS "  Algorithms:  ${CRYPTO_ALGS}")
message(STATUS "  CUDA:        ${CRYPTO_ENABLE_CUDA}")
message(STATUS "  Metal:       ${CRYPTO_ENABLE_METAL}")
message(STATUS "  WGSL:        ${CRYPTO_ENABLE_WGSL}")
message(STATUS "  Tests:       ${CRYPTO_BUILD_TESTS}")
message(STATUS "=================================================")

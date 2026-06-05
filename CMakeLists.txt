cmake_minimum_required(VERSION 3.20)
project(kinet_crypto VERSION 1.0.0 LANGUAGES C CXX)

# =============================================================================
# kinet-labs/crypto - canonical GPU-accelerated cryptographic primitives
# =============================================================================
#
# Layout (one directory per algorithm):
#
#   c-abi/kinet_crypto.h           public C ABI for Go cgo + Rust bindgen
#   c-abi/c_kinet_crypto.cpp       top-level dispatcher (GPU control + version)
#   include/kinet/crypto/<alg>.h   per-algorithm public C header
#   <alg>/cpp/                   first-party CPU implementation
#   <alg>/gpu/{cuda,metal,wgsl}  GPU kernels + drivers
#   <alg>/c-abi/c_<alg>.{h,cpp}  algorithm-internal C ABI shim
#   <alg>/test/                  CPU + GPU correctness + determinism tests
#
# 29 algorithms: aead attestation blake2b blake3 bls bn254 cggmp21 ed25519
#                evm256 frost ipa keccak kzg lamport mldsa mlkem modexp ntt
#                pedersen poly_mul poseidon ringtail ripemd160 secp256k1
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

option(KINET_CRYPTO_ENABLE_CUDA  "Build CUDA drivers"  OFF)
option(KINET_CRYPTO_ENABLE_METAL "Build Metal drivers" OFF)
option(KINET_CRYPTO_ENABLE_WGSL  "Build WGSL drivers"  OFF)
option(KINET_CRYPTO_BUILD_TESTS  "Build crypto tests"  ON)

if(APPLE)
    set(KINET_CRYPTO_ENABLE_METAL ON CACHE BOOL "Build Metal drivers" FORCE)
endif()

if(KINET_CRYPTO_ENABLE_CUDA)
    enable_language(CUDA)
    add_compile_definitions(KINET_CRYPTO_HAS_CUDA=1)
endif()
if(KINET_CRYPTO_ENABLE_METAL)
    enable_language(OBJCXX)
    add_compile_definitions(KINET_CRYPTO_HAS_METAL=1)
endif()
if(KINET_CRYPTO_ENABLE_WGSL)
    add_compile_definitions(KINET_CRYPTO_HAS_WGSL=1)
endif()

# Public include dir reachable from every translation unit as
#   #include <kinet_crypto.h>           (umbrella surface)
#   #include <kinet/crypto/<alg>.h>     (per-algorithm surface)
include_directories(BEFORE
    ${CMAKE_CURRENT_SOURCE_DIR}/c-abi
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# 29 canonical algorithms (alphabetical).
set(KINET_CRYPTO_ALGS
    aead
    attestation
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

foreach(_alg ${KINET_CRYPTO_ALGS})
    add_subdirectory(${_alg})
endforeach()

# gpukit -- common GPU kernel-pattern library (prefix_sum, compaction,
# radix_sort, batch_inversion, merkle_compose, transcript_root, ntt). Lives
# alongside the algorithms because it is a building-block layer they consume.
option(KINET_GPUKIT_ENABLE_CUDA "Build gpukit CUDA driver" OFF)
option(KINET_GPUKIT_ENABLE_WGSL "Build gpukit WGSL driver" ${KINET_CRYPTO_ENABLE_WGSL})
add_subdirectory(gpukit)

# Top-level dispatcher (GPU control + version) lives next to the public header.
add_library(crypto STATIC c-abi/c_kinet_crypto.cpp)
target_include_directories(crypto
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/c-abi>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_compile_features(crypto PUBLIC cxx_std_20)
set_target_properties(crypto PROPERTIES POSITION_INDEPENDENT_CODE ON)
foreach(_alg ${KINET_CRYPTO_ALGS})
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

if(KINET_CRYPTO_BUILD_TESTS)
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
    target_link_libraries(secp256k1_test PRIVATE secp256k1_cpu)
    target_include_directories(secp256k1_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/cpp
    )
    add_test(NAME secp256k1_test COMMAND secp256k1_test)

    add_executable(secp256k1_batch_inv_test secp256k1/test/secp256k1_batch_inv_test.cpp)
    target_link_libraries(secp256k1_batch_inv_test PRIVATE secp256k1_cpu)
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
                ENVIRONMENT "KINET_CRYPTO_SECP256K1_METALLIB=${_secp_lib}")
        endif()
    endif()
endif()

message(STATUS "=================================================")
message(STATUS "kinet-labs/crypto v${PROJECT_VERSION}")
message(STATUS "  Algorithms:  ${KINET_CRYPTO_ALGS}")
message(STATUS "  CUDA:        ${KINET_CRYPTO_ENABLE_CUDA}")
message(STATUS "  Metal:       ${KINET_CRYPTO_ENABLE_METAL}")
message(STATUS "  WGSL:        ${KINET_CRYPTO_ENABLE_WGSL}")
message(STATUS "  Tests:       ${KINET_CRYPTO_BUILD_TESTS}")
message(STATUS "=================================================")

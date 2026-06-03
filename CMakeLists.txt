cmake_minimum_required(VERSION 3.20)
project(kinet-crypto VERSION 1.0.0 LANGUAGES CXX OBJCXX)

# =============================================================================
# Kinet Crypto Library - GPU-Accelerated Cryptographic Primitives
# =============================================================================
#
# Depends on: kinet-labs/lattice (for NTT operations)
#             kinet-labs/gpu (optional, for MLX acceleration)
#
# Build Options:
#   -DWITH_GPU=ON       Enable GPU acceleration via kinet-labs/gpu (MLX)
#   -DWITH_METAL=ON     Enable Metal compute shaders for BLS12-381 (macOS)
#   -DBUILD_SHARED_LIBS=ON Build shared libraries (default)
#
# Usage:
#   mkdir build && cd build
#   cmake -DWITH_METAL=ON -DCMAKE_PREFIX_PATH=../lattice/build ..
#   make -j$(sysctl -n hw.ncpu)
#
# =============================================================================

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(KinetLibrary)
include(GNUInstallDirs)

# Options
option(WITH_GPU "Build with GPU acceleration via kinet-labs/gpu (MLX)" OFF)
option(WITH_METAL "Build with Metal compute shaders for BLS12-381" ON)

# =============================================================================
# Metal Compute Shader Compilation (macOS)
# =============================================================================
# Compiles Metal shaders into two separate metallibs:
#
# kinet_crypto.metallib (classical cryptography):
#   - bls12_381.metal: BLS12-381 signatures, MSM, batch verify
#   - blake3.metal: BLAKE3 hash (batch)
#   - kzg.metal: KZG polynomial commitments (EIP-4844)
#
# kinet_zk.metallib (zero-knowledge operations):
#   - bn254.metal: BN254 pairing operations
#   - goldilocks.metal: Goldilocks field for STARK
#   - poseidon.metal: Poseidon hash (Goldilocks)
#   - poseidon2_bn254.metal: Poseidon2 hash (BN254/Fr)
#   - msm.metal: Multi-scalar multiplication

set(METAL_RESOURCES)
if(APPLE AND WITH_METAL)
    message(STATUS "Enabling Metal compute shaders")

    find_program(XCRUN xcrun)
    if(XCRUN)
        # Classical crypto shaders (kinet_crypto.metallib)
        set(CRYPTO_SHADERS
            "${CMAKE_CURRENT_SOURCE_DIR}/src/metal/bls12_381.metal"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/metal/blake3.metal"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/metal/kzg.metal"
        )

        # ZK-specific shaders (kinet_zk.metallib)
        set(ZK_SHADERS
            "${CMAKE_CURRENT_SOURCE_DIR}/src/metal/bn254.metal"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/metal/goldilocks.metal"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/metal/poseidon.metal"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/metal/poseidon2_bn254.metal"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/metal/msm.metal"
        )

        set(CRYPTO_AIR_FILES)
        set(ZK_AIR_FILES)
        set(CRYPTO_LIB "${CMAKE_CURRENT_BINARY_DIR}/kinet_crypto.metallib")
        set(ZK_LIB "${CMAKE_CURRENT_BINARY_DIR}/kinet_zk.metallib")

        # Helper function to compile shaders
        function(compile_metal_shaders SHADER_LIST AIR_LIST_VAR PREFIX)
            set(AIR_FILES)
            foreach(SHADER ${${SHADER_LIST}})
                if(EXISTS "${SHADER}")
                    get_filename_component(SHADER_NAME ${SHADER} NAME_WE)
                    set(AIR_FILE "${CMAKE_CURRENT_BINARY_DIR}/${SHADER_NAME}.air")
                    list(APPEND AIR_FILES ${AIR_FILE})

                    add_custom_command(
                        OUTPUT ${AIR_FILE}
                        COMMAND ${XCRUN} -sdk macosx metal -c ${SHADER} -o ${AIR_FILE}
                        DEPENDS ${SHADER}
                        COMMENT "Compiling Metal shader [${PREFIX}]: ${SHADER_NAME}.metal"
                    )
                    message(STATUS "  [${PREFIX}] ${SHADER_NAME}.metal")
                else()
                    message(WARNING "Metal shader not found: ${SHADER}")
                endif()
            endforeach()
            set(${AIR_LIST_VAR} ${AIR_FILES} PARENT_SCOPE)
        endfunction()

        # Compile crypto shaders
        message(STATUS "Building kinet_crypto.metallib (classical crypto):")
        compile_metal_shaders(CRYPTO_SHADERS CRYPTO_AIR_FILES "crypto")

        # Compile ZK shaders
        message(STATUS "Building kinet_zk.metallib (ZK operations):")
        compile_metal_shaders(ZK_SHADERS ZK_AIR_FILES "zk")

        # Link crypto .air files -> kinet_crypto.metallib
        if(CRYPTO_AIR_FILES)
            add_custom_command(
                OUTPUT ${CRYPTO_LIB}
                COMMAND ${XCRUN} -sdk macosx metallib ${CRYPTO_AIR_FILES} -o ${CRYPTO_LIB}
                DEPENDS ${CRYPTO_AIR_FILES}
                COMMENT "Linking Metal library: kinet_crypto.metallib"
            )
        endif()

        # Link ZK .air files -> kinet_zk.metallib
        if(ZK_AIR_FILES)
            add_custom_command(
                OUTPUT ${ZK_LIB}
                COMMAND ${XCRUN} -sdk macosx metallib ${ZK_AIR_FILES} -o ${ZK_LIB}
                DEPENDS ${ZK_AIR_FILES}
                COMMENT "Linking Metal library: kinet_zk.metallib"
            )
        endif()

        # Create target for both metallibs
        set(ALL_METALLIBS)
        if(CRYPTO_AIR_FILES)
            list(APPEND ALL_METALLIBS ${CRYPTO_LIB})
        endif()
        if(ZK_AIR_FILES)
            list(APPEND ALL_METALLIBS ${ZK_LIB})
        endif()

        if(ALL_METALLIBS)
            add_custom_target(metal_shaders DEPENDS ${ALL_METALLIBS})
            set(METAL_RESOURCES ${ALL_METALLIBS})
        endif()
    else()
        message(WARNING "xcrun not found, Metal shaders will be compiled at runtime")
    endif()
endif()

# =============================================================================
# Source Files
# =============================================================================

set(CRYPTO_SOURCES
    src/crypto.cpp
)

set(CRYPTO_HEADERS
    include/kinet/crypto/crypto.h
)

if(APPLE AND WITH_METAL)
    list(APPEND CRYPTO_SOURCES src/metal_bls.mm)
    list(APPEND CRYPTO_HEADERS include/kinet/crypto/metal_bls.h)
endif()

# =============================================================================
# Dependencies
# =============================================================================

set(CRYPTO_DEPS)
if(WITH_GPU)
    list(APPEND CRYPTO_DEPS kinet-gpu)
endif()
# kinet-lattice is optional dependency for NTT operations
find_package(kinet-lattice CONFIG QUIET)
if(kinet-lattice_FOUND)
    list(APPEND CRYPTO_DEPS kinet-lattice)
endif()

# Frameworks
set(CRYPTO_FRAMEWORKS)
if(APPLE)
    list(APPEND CRYPTO_FRAMEWORKS Metal Foundation Security)
endif()

# =============================================================================
# Library Target (using shared KinetLibrary helper)
# =============================================================================

kinet_add_library(
    NAME crypto
    VERSION ${PROJECT_VERSION}
    DESCRIPTION "GPU-accelerated cryptographic primitives for Kinet (BLS12-381, ML-DSA)"
    SOURCES ${CRYPTO_SOURCES}
    HEADERS ${CRYPTO_HEADERS}
    DEPENDENCIES ${CRYPTO_DEPS}
    FRAMEWORKS ${CRYPTO_FRAMEWORKS}
    RESOURCES ${METAL_RESOURCES}
    SHARED
)

set(TARGET_NAME "kinet-crypto")

# Add dependency on Metal shader compilation
if(TARGET metal_shaders)
    add_dependencies(${TARGET_NAME} metal_shaders)
endif()

# Compile definitions
if(APPLE AND WITH_METAL)
    target_compile_definitions(${TARGET_NAME} PRIVATE WITH_METAL)
endif()

if(WITH_GPU)
    target_compile_definitions(${TARGET_NAME} PRIVATE WITH_GPU WITH_MLX)
endif()

# =============================================================================
# CI Relocatability Check
# =============================================================================

kinet_verify_relocatable(${TARGET_NAME})

# =============================================================================
# Summary
# =============================================================================

message(STATUS "=================================================")
message(STATUS "Kinet Crypto Library Configuration:")
message(STATUS "  Package:        kinet-crypto")
message(STATUS "  Target:         kinet::crypto")
message(STATUS "  Library:        libkinetcrypto.{dylib,so}")
message(STATUS "  Version:        ${PROJECT_VERSION}")
message(STATUS "  Metal BLS:      ${WITH_METAL}")
message(STATUS "  GPU (kinet-gpu):  ${WITH_GPU}")
message(STATUS "  kinet-lattice:    ${kinet-lattice_FOUND}")
message(STATUS "  Shared:         ${BUILD_SHARED_LIBS}")
message(STATUS "  Install Prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "=================================================")

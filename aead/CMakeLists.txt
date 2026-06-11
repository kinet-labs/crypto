# aead - first-party ChaCha20-Poly1305 (RFC 8439) + AES-256-GCM (SP 800-38D).
# Pure C++ body in cpp/aead.cpp; C-ABI shim in c-abi/c_aead.cpp.
# Optional Metal / CUDA / WGSL drivers for batched per-message AEAD on GPUs.

include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    aead
    SOURCES cpp/aead.cpp
    HEADERS cpp/aead.hpp
    CABI    c-abi/c_aead.cpp
)

# =============================================================================
# Metal drivers (Apple GPUs).
# =============================================================================
if(APPLE AND KINET_CRYPTO_ENABLE_METAL)
    add_library(aead_batch_metal STATIC
        gpu/metal/aead_batch_driver.mm)
    target_compile_features(aead_batch_metal PUBLIC cxx_std_20)
    set_target_properties(aead_batch_metal PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        COMPILE_FLAGS "-fobjc-arc"
    )
    target_link_libraries(aead_batch_metal PUBLIC
        "-framework Metal" "-framework Foundation")

    add_library(aead_aes_gcm_metal STATIC
        gpu/metal/aes_gcm_driver.mm)
    target_compile_features(aead_aes_gcm_metal PUBLIC cxx_std_20)
    set_target_properties(aead_aes_gcm_metal PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        COMPILE_FLAGS "-fobjc-arc"
    )
    target_link_libraries(aead_aes_gcm_metal PUBLIC
        "-framework Metal" "-framework Foundation")
endif()

# =============================================================================
# CUDA drivers + determinism test.
#
# The .cu files compile only when KINET_CRYPTO_ENABLE_CUDA is ON (NVCC required).
# The host driver compiles on every host: with KINET_AEAD_HAVE_CUDA defined it
# launches the kernels; without, it returns -1 from every entry point so the
# determinism test prints a "build-only" banner on Apple.
# =============================================================================

# Always build the host driver (stub or real). On Apple this gives us the
# build-only path (compiles, links, returns -1). On Linux+CUDA CI we set
# KINET_CRYPTO_ENABLE_CUDA=ON which flips the driver into real-dispatch mode
# and additionally compiles the .cu kernels.

add_library(aead_cuda_driver STATIC gpu/cuda/aead_driver_cuda.cpp)
target_include_directories(aead_cuda_driver
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/gpu/cuda>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cpp>
)
target_compile_features(aead_cuda_driver PUBLIC cxx_std_20)
set_target_properties(aead_cuda_driver PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(KINET_CRYPTO_ENABLE_CUDA)
    enable_language(CUDA)
    add_library(aead_cuda_kernels STATIC
        gpu/cuda/chacha20_poly1305.cu
        gpu/cuda/aes_gcm.cu)
    set_target_properties(aead_cuda_kernels PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        CUDA_SEPARABLE_COMPILATION ON
    )
    target_include_directories(aead_cuda_kernels
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/gpu/cuda>)
    target_compile_definitions(aead_cuda_driver PRIVATE KINET_AEAD_HAVE_CUDA=1)
    target_link_libraries(aead_cuda_driver PUBLIC aead_cuda_kernels)
    find_package(CUDAToolkit REQUIRED)
    target_link_libraries(aead_cuda_driver PUBLIC CUDA::cudart)
endif()

# Test executables are added at the top-level CMakeLists.txt where
# enable_testing() has been called before us. The library targets above
# are sufficient for the parent to wire test binaries.

# =============================================================================
# WGSL driver (compiles WGSL via wgpu-native or Dawn; outputs bound through
# C ABI). On Apple, byte-equality is enforced if wgpu-native is on the system;
# otherwise the test self-skips. On Linux/CI, same behavior with Dawn.
# =============================================================================

# Concatenate WGSL sources into a header that the host driver embeds.
set(AEAD_WGSL_DIR    "${CMAKE_CURRENT_SOURCE_DIR}/gpu/wgsl")
set(AEAD_WGSL_HEADER "${CMAKE_CURRENT_BINARY_DIR}/aead_wgsl_sources.h")
file(WRITE "${AEAD_WGSL_HEADER}" "// Auto-generated. Do not edit.\n#pragma once\n\n")
foreach(_SRC chacha20_poly1305.wgsl aes_gcm.wgsl)
    get_filename_component(_NAME ${_SRC} NAME_WE)
    string(REGEX REPLACE "^chacha20_poly1305$" "ChaCha20Poly1305" _SHORT "${_NAME}")
    string(REGEX REPLACE "^aes_gcm$"           "AesGcm"           _SHORT "${_SHORT}")
    file(READ "${AEAD_WGSL_DIR}/${_SRC}" _CONTENT)
    file(APPEND "${AEAD_WGSL_HEADER}"
        "// ---- ${_SRC} ----\n"
        "static constexpr char kAEAD_WGSL_${_SHORT}[] = R\"AEADWGSL(\n${_CONTENT}\n)AEADWGSL\";\n\n")
endforeach()

# Locate wgpu-native (Homebrew) or Dawn.
set(_AEAD_WGPU_FOUND FALSE)
find_path(_AEAD_WGPU_INCLUDE webgpu.h
    HINTS /opt/homebrew/include /usr/local/include /usr/include)
find_library(_AEAD_WGPU_LIB NAMES wgpu_native wgpu
    HINTS /opt/homebrew/lib /usr/local/lib /usr/lib)
if(_AEAD_WGPU_INCLUDE AND _AEAD_WGPU_LIB)
    set(_AEAD_WGPU_FOUND TRUE)
endif()

add_library(aead_wgpu_driver STATIC gpu/wgsl/aead_driver_wgpu.cpp)
target_include_directories(aead_wgpu_driver
    PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/gpu/wgsl"
        "${CMAKE_CURRENT_SOURCE_DIR}/cpp"
)
target_compile_features(aead_wgpu_driver PUBLIC cxx_std_20)
set_target_properties(aead_wgpu_driver PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(_AEAD_WGPU_FOUND)
    target_include_directories(aead_wgpu_driver PRIVATE ${_AEAD_WGPU_INCLUDE})
    target_link_libraries(aead_wgpu_driver PUBLIC ${_AEAD_WGPU_LIB})
    target_compile_definitions(aead_wgpu_driver PRIVATE
        KINET_AEAD_HAS_WEBGPU=1
        KINET_AEAD_HAS_WGPU_NATIVE=1)
    message(STATUS "[aead-wgsl] wgpu-native: ${_AEAD_WGPU_LIB}")
else()
    message(STATUS "[aead-wgsl] wgpu-native: NOT FOUND (driver compiles to stub)")
endif()

# See note above: aead_wgsl_determinism_test is added at the top-level
# CMakeLists.txt after enable_testing() has run.

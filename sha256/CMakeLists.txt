# sha256 - SHA-256 (FIPS 180-4)
include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    sha256
    SOURCES cpp/sha256.cpp
    HEADERS cpp/sha256.hpp
    CABI    c-abi/c_sha256.cpp
)

# Batched SHA-256 Metal driver (one thread per input). Byte-equal to
# sha256/cpp/sha256.cpp::sha256() for arbitrary-length inputs.
if(APPLE AND CRYPTO_ENABLE_METAL)
    add_library(sha256_batch_metal STATIC
        gpu/metal/sha256_batch_driver.mm)
    target_compile_features(sha256_batch_metal PUBLIC cxx_std_20)
    set_target_properties(sha256_batch_metal PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        COMPILE_FLAGS "-fobjc-arc"
    )
    target_link_libraries(sha256_batch_metal PUBLIC
        "-framework Metal"
        "-framework Foundation"
    )
endif()

# =============================================================================
# CUDA driver (host TU + .cu kernel). Build modes:
#   * KINET_CRYPTO_ENABLE_CUDA=ON  -> compile sha256.cu via nvcc; link to a real
#                                   driver that talks to the CUDA runtime.
#   * KINET_CRYPTO_ENABLE_CUDA=OFF -> compile only the host shim in stub mode
#                                   so the test harness can call the C ABI
#                                   on Apple/non-CUDA hosts (returns 0
#                                   "available?" -> false; skips compare).
# =============================================================================
add_library(sha256_batch_cuda STATIC
    gpu/cuda/sha256_driver.cpp)
target_include_directories(sha256_batch_cuda PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/gpu/cuda)
target_compile_features(sha256_batch_cuda PUBLIC cxx_std_20)
set_target_properties(sha256_batch_cuda PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(KINET_CRYPTO_ENABLE_CUDA)
    target_compile_definitions(sha256_batch_cuda PRIVATE KINET_SHA256_HAVE_CUDA=1)
    # Compile the kernel via nvcc and link as a CUDA TU.
    target_sources(sha256_batch_cuda PRIVATE gpu/cuda/sha256.cu)
    set_source_files_properties(gpu/cuda/sha256.cu PROPERTIES LANGUAGE CUDA)
    set_target_properties(sha256_batch_cuda PROPERTIES
        CUDA_SEPARABLE_COMPILATION ON)
endif()

# =============================================================================
# WGSL driver (WebGPU). The WGSL source is concatenated into a header at
# build time so the driver embeds the kernel source as a string literal.
# Compiles to stub mode unless wgpu-native (or Dawn) is found on the host.
# =============================================================================
set(_SHA256_WGSL_HEADER "${CMAKE_CURRENT_BINARY_DIR}/sha256_wgsl_sources.h")
file(WRITE ${_SHA256_WGSL_HEADER}
    "// Auto-generated. Do not edit.\n"
    "#pragma once\n\n")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/gpu/wgsl/sha256.wgsl" _SHA256_WGSL_SRC)
file(APPEND ${_SHA256_WGSL_HEADER}
    "static constexpr char kSHA256_WGSL_Source[] = R\"SHAWGSL(\n"
    "${_SHA256_WGSL_SRC}\n"
    ")SHAWGSL\";\n")

add_library(sha256_batch_wgpu STATIC gpu/wgsl/sha256_driver_wgpu.cpp)
target_include_directories(sha256_batch_wgpu
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/gpu/wgsl
    PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_compile_features(sha256_batch_wgpu PUBLIC cxx_std_20)
set_target_properties(sha256_batch_wgpu PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(KINET_CRYPTO_ENABLE_WGSL)
    find_path(_SHA256_WGPU_INCLUDE webgpu.h
        HINTS /opt/homebrew/include /usr/local/include /usr/include)
    find_library(_SHA256_WGPU_LIB NAMES wgpu_native wgpu
        HINTS /opt/homebrew/lib /usr/local/lib /usr/lib)
    if(_SHA256_WGPU_INCLUDE AND _SHA256_WGPU_LIB)
        target_include_directories(sha256_batch_wgpu PRIVATE ${_SHA256_WGPU_INCLUDE})
        target_link_libraries(sha256_batch_wgpu PUBLIC ${_SHA256_WGPU_LIB})
        target_compile_definitions(sha256_batch_wgpu PRIVATE
            KINET_SHA256_HAS_WEBGPU=1
            KINET_SHA256_HAS_WGPU_NATIVE=1)
        message(STATUS "[sha256] wgpu-native: ${_SHA256_WGPU_LIB}")
    else()
        message(STATUS "[sha256] wgpu-native: NOT FOUND (driver -> stub mode)")
    endif()
endif()

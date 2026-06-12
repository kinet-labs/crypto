# ripemd160 - RIPEMD-160 (Ethereum precompile 0x03)
include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    ripemd160
    SOURCES cpp/ripemd160.cpp
    HEADERS cpp/ripemd160.hpp
    CABI    c-abi/c_ripemd160.cpp
)

# Batched RIPEMD-160 Metal driver (one thread per input). Byte-equal to
# ripemd160/cpp/ripemd160.cpp::ripemd160().
if(APPLE AND CRYPTO_ENABLE_METAL)
    add_library(ripemd160_batch_metal STATIC
        gpu/metal/ripemd160_batch_driver.mm)
    target_compile_features(ripemd160_batch_metal PUBLIC cxx_std_20)
    set_target_properties(ripemd160_batch_metal PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        COMPILE_FLAGS "-fobjc-arc"
    )
    target_link_libraries(ripemd160_batch_metal PUBLIC
        "-framework Metal"
        "-framework Foundation"
    )
endif()

# =============================================================================
# CUDA driver (host TU + .cu kernel). Build modes:
#   * CRYPTO_ENABLE_CUDA=ON  -> compile ripemd160.cu via nvcc; link to a
#                                   real driver that talks to the CUDA runtime.
#   * CRYPTO_ENABLE_CUDA=OFF -> compile only the host shim in stub mode so
#                                   the test harness can call the C ABI on
#                                   Apple/non-CUDA hosts (returns 0
#                                   "available?" -> false; skips compare).
# =============================================================================
add_library(ripemd160_batch_cuda STATIC
    gpu/cuda/ripemd160_driver.cpp)
target_include_directories(ripemd160_batch_cuda PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/gpu/cuda)
target_compile_features(ripemd160_batch_cuda PUBLIC cxx_std_20)
set_target_properties(ripemd160_batch_cuda PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(CRYPTO_ENABLE_CUDA)
    target_compile_definitions(ripemd160_batch_cuda PRIVATE KINET_RIPEMD160_HAVE_CUDA=1)
    target_sources(ripemd160_batch_cuda PRIVATE gpu/cuda/ripemd160.cu)
    set_source_files_properties(gpu/cuda/ripemd160.cu PROPERTIES LANGUAGE CUDA)
    set_target_properties(ripemd160_batch_cuda PROPERTIES
        CUDA_SEPARABLE_COMPILATION ON)
endif()

# =============================================================================
# WGSL driver (WebGPU). The WGSL source is concatenated into a header at
# build time so the driver embeds the kernel source as a string literal.
# Compiles to stub mode unless wgpu-native (or Dawn) is found on the host.
# =============================================================================
set(_RIPEMD160_WGSL_HEADER "${CMAKE_CURRENT_BINARY_DIR}/ripemd160_wgsl_sources.h")
file(WRITE ${_RIPEMD160_WGSL_HEADER}
    "// Auto-generated. Do not edit.\n"
    "#pragma once\n\n")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/gpu/wgsl/ripemd160.wgsl" _RIPEMD160_WGSL_SRC)
file(APPEND ${_RIPEMD160_WGSL_HEADER}
    "static constexpr char kRIPEMD160_WGSL_Source[] = R\"RMDWGSL(\n"
    "${_RIPEMD160_WGSL_SRC}\n"
    ")RMDWGSL\";\n")

add_library(ripemd160_batch_wgpu STATIC gpu/wgsl/ripemd160_driver_wgpu.cpp)
target_include_directories(ripemd160_batch_wgpu
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/gpu/wgsl
    PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_compile_features(ripemd160_batch_wgpu PUBLIC cxx_std_20)
set_target_properties(ripemd160_batch_wgpu PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(CRYPTO_ENABLE_WGSL)
    find_path(_RIPEMD160_WGPU_INCLUDE webgpu.h
        HINTS /opt/homebrew/include /usr/local/include /usr/include)
    find_library(_RIPEMD160_WGPU_LIB NAMES wgpu_native wgpu
        HINTS /opt/homebrew/lib /usr/local/lib /usr/lib)
    if(_RIPEMD160_WGPU_INCLUDE AND _RIPEMD160_WGPU_LIB)
        target_include_directories(ripemd160_batch_wgpu PRIVATE ${_RIPEMD160_WGPU_INCLUDE})
        target_link_libraries(ripemd160_batch_wgpu PUBLIC ${_RIPEMD160_WGPU_LIB})
        target_compile_definitions(ripemd160_batch_wgpu PRIVATE
            KINET_RIPEMD160_HAS_WEBGPU=1
            KINET_RIPEMD160_HAS_WGPU_NATIVE=1)
        message(STATUS "[ripemd160] wgpu-native: ${_RIPEMD160_WGPU_LIB}")
    else()
        message(STATUS "[ripemd160] wgpu-native: NOT FOUND (driver -> stub mode)")
    endif()
endif()

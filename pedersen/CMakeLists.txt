include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    pedersen
    SOURCES cpp/pedersen.cpp c-abi/c_pedersen.cpp
    HEADERS cpp/pedersen.hpp
    CABI    c-abi/c_pedersen.cpp
)

# pedersen depends on bn254 (Fp/Fr/G1 + RFC 9380 hash-to-curve).
target_link_libraries(pedersen_cpu PUBLIC bn254_cpu)
target_link_libraries(pedersen     PUBLIC bn254_cpu)
target_include_directories(pedersen_cpu PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/bn254/cpp>
)
target_include_directories(pedersen PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/bn254/cpp>
)

# Batched Pedersen vector-commitment Metal driver (BN254 G1).  Two-stage
# pipeline (pedersen_pointmul + pedersen_reduce_add); byte-equal to the Go
# canonical at github.com/kinet-labs/crypto/pedersen.
if(APPLE AND KINET_CRYPTO_ENABLE_METAL)
    add_library(pedersen_metal STATIC
        gpu/metal/pedersen_driver.mm)
    target_compile_features(pedersen_metal PUBLIC cxx_std_20)
    set_target_properties(pedersen_metal PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        COMPILE_FLAGS "-fobjc-arc"
    )
    target_include_directories(pedersen_metal PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/gpu/metal
    )
    target_link_libraries(pedersen_metal PUBLIC
        "-framework Metal"
        "-framework Foundation"
    )
endif()

# Batched Pedersen CUDA driver.  pedersen.cu compiles in two flavours:
#   * with nvcc (KINET_CRYPTO_ENABLE_CUDA=ON, project enables CUDA language) it
#     produces real device kernels and the host driver links them.
#   * without CUDA the host driver compiles in stub mode (returns -1) so
#     downstream tests still build but skip dispatch.
if(KINET_CRYPTO_ENABLE_CUDA)
    add_library(pedersen_cuda STATIC
        gpu/cuda/pedersen.cu
        gpu/cuda/pedersen_driver_cuda.cpp)
    set_source_files_properties(gpu/cuda/pedersen.cu PROPERTIES LANGUAGE CUDA)
    target_compile_definitions(pedersen_cuda PRIVATE KINET_PEDERSEN_HAVE_CUDA=1)
    set_target_properties(pedersen_cuda PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        CUDA_SEPARABLE_COMPILATION ON)
    target_include_directories(pedersen_cuda PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/gpu/cuda)
else()
    # Compile only the host driver stub so consumers can still link a
    # symbol-complete pedersen_cuda library on hosts without nvcc.
    add_library(pedersen_cuda STATIC
        gpu/cuda/pedersen_driver_cuda.cpp)
    set_target_properties(pedersen_cuda PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_include_directories(pedersen_cuda PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/gpu/cuda)
endif()
target_compile_features(pedersen_cuda PUBLIC cxx_std_20)

# Batched Pedersen WebGPU/WGSL driver.  The single shader source is embedded
# at configure time as a const char* so the driver can submit it via Dawn /
# wgpu-native without runtime file I/O.
set(_ped_wgsl_src    ${CMAKE_CURRENT_SOURCE_DIR}/gpu/wgsl/pedersen.wgsl)
set(_ped_wgsl_embed  ${CMAKE_CURRENT_BINARY_DIR}/pedersen_wgsl_source.h)
file(READ ${_ped_wgsl_src} _ped_wgsl_content)
file(WRITE  ${_ped_wgsl_embed} "// Auto-generated. Do not edit.\n#pragma once\n\n")
file(APPEND ${_ped_wgsl_embed}
    "static constexpr char kPedersenWGSL[] = R\"PEDWGSL(\n${_ped_wgsl_content}\n)PEDWGSL\";\n")

add_library(pedersen_wgpu STATIC
    gpu/wgsl/pedersen_driver_wgpu.cpp)
target_compile_features(pedersen_wgpu PUBLIC cxx_std_20)
set_target_properties(pedersen_wgpu PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(pedersen_wgpu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/gpu/wgsl
    ${CMAKE_CURRENT_BINARY_DIR})

if(KINET_CRYPTO_ENABLE_WGSL)
    find_path(_PED_WGPU_INCLUDE webgpu.h
        HINTS /opt/homebrew/include /usr/local/include /usr/include)
    find_library(_PED_WGPU_LIB NAMES wgpu_native wgpu
        HINTS /opt/homebrew/lib /usr/local/lib /usr/lib)
    if(_PED_WGPU_INCLUDE AND _PED_WGPU_LIB)
        target_include_directories(pedersen_wgpu PRIVATE ${_PED_WGPU_INCLUDE})
        target_link_libraries(pedersen_wgpu PUBLIC ${_PED_WGPU_LIB})
        target_compile_definitions(pedersen_wgpu PRIVATE
            KINET_PEDERSEN_HAS_WEBGPU=1
            KINET_PEDERSEN_HAS_WGPU_NATIVE=1)
        message(STATUS "[pedersen-wgsl] wgpu-native: ${_PED_WGPU_LIB}")
    else()
        message(STATUS "[pedersen-wgsl] wgpu-native: NOT FOUND (driver compiles to stub)")
    endif()
endif()

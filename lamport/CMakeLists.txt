# lamport - Lamport-SHA256 one-time signatures (LP-2506).
#
# CPU body is the canonical oracle. The Metal / CUDA / WGSL kernels all hash
# 32-byte preimages with single-block FIPS 180-4 padding and are byte-equal to
# lamport/cpp/lamport.cpp.

include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    lamport
    SOURCES cpp/lamport.cpp
    HEADERS cpp/lamport.hpp
    CABI    c-abi/c_lamport.cpp
    METAL_DRIVER  gpu/metal/lamport_driver.mm
    METAL_HEADERS gpu/metal/lamport_driver.h
    CUDA_SOURCES  gpu/cuda/lamport.cu
)

# CPU body uses sha256/cpp/sha256.hpp for the canonical hash. Bring in the
# sha256 CPU lib and its include path.
target_link_libraries(lamport_cpu PUBLIC sha256_cpu)
target_include_directories(lamport_cpu PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/sha256/cpp>
)
target_include_directories(lamport PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/sha256/cpp>
)

# Always-built host oracles for the CUDA + WGSL kernels. These exist so the
# determinism tests can run on hosts without an NVIDIA / WebGPU runtime —
# the oracle is line-for-line the same arithmetic as the kernel.
add_library(lamport_cuda_oracle STATIC gpu/cuda/lamport_cuda_oracle.cpp)
target_compile_features(lamport_cuda_oracle PUBLIC cxx_std_20)
set_target_properties(lamport_cuda_oracle PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(lamport_wgsl_oracle STATIC gpu/wgsl/lamport_wgsl_oracle.cpp)
target_compile_features(lamport_wgsl_oracle PUBLIC cxx_std_20)
set_target_properties(lamport_wgsl_oracle PROPERTIES POSITION_INDEPENDENT_CODE ON)

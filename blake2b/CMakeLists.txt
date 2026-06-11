# blake2b - BLAKE2b RFC 7693
include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    blake2b
    SOURCES cpp/blake2b.cpp c-abi/blake2b_full.cpp
    HEADERS cpp/blake2b.hpp
    CABI    c-abi/c_blake2b.cpp
)

# Batched BLAKE2b-512 Metal driver (one thread per input). Byte-equal to
# blake2b/c-abi/blake2b_full.cpp::hash().
if(APPLE AND CRYPTO_ENABLE_METAL)
    add_library(blake2b_batch_metal STATIC
        gpu/metal/blake2b_batch_driver.mm)
    target_compile_features(blake2b_batch_metal PUBLIC cxx_std_20)
    set_target_properties(blake2b_batch_metal PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        COMPILE_FLAGS "-fobjc-arc"
    )
    target_link_libraries(blake2b_batch_metal PUBLIC
        "-framework Metal"
        "-framework Foundation"
    )
endif()

# Batched BLAKE2b CUDA kernel + host-emulation entry point.
# When KINET_CRYPTO_ENABLE_CUDA=ON the .cu file is compiled by nvcc with the
# real __global__ kernel exposed as blake2b_jobs. When CUDA is off (default
# CPU-only build) the same .cu file compiles as host C++ via the
# __CUDA_ARCH__ shim and exposes blake2b_batch_cuda_host for the
# determinism test, which is byte-equal to the device kernel by construction.
if(KINET_CRYPTO_ENABLE_CUDA)
    add_library(blake2b_batch_cuda STATIC gpu/cuda/blake2b.cu)
    set_target_properties(blake2b_batch_cuda PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        CUDA_SEPARABLE_COMPILATION ON)
else()
    add_library(blake2b_batch_cuda STATIC gpu/cuda/blake2b.cu)
    set_source_files_properties(gpu/cuda/blake2b.cu PROPERTIES LANGUAGE CXX)
    target_compile_features(blake2b_batch_cuda PUBLIC cxx_std_20)
    set_target_properties(blake2b_batch_cuda PROPERTIES
        POSITION_INDEPENDENT_CODE ON)
endif()

# Batched BLAKE2b WGSL host-emulation entry point. The .wgsl kernel is
# shipped alongside; the host emulator mirrors it byte-for-byte (same
# vec2<u32>-emulated u64 math) so determinism testing succeeds on systems
# without a wgpu runtime.
add_library(blake2b_batch_wgsl STATIC gpu/wgsl/blake2b_wgsl_host.cpp)
target_compile_features(blake2b_batch_wgsl PUBLIC cxx_std_20)
set_target_properties(blake2b_batch_wgsl PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

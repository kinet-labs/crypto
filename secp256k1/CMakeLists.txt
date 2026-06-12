# secp256k1 - Bitcoin / Ethereum curve (first-party ecrecover)
# CPU body lives in cpp/ecrecover.cpp + cpp/{curve,field}.hpp; no third-party
# crypto library is linked.

include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    secp256k1
    SOURCES cpp/ecrecover.cpp cpp/batch_inv.cpp cpp/ecdsa.cpp
    HEADERS ../include/kinet/crypto/secp256k1.h
            cpp/curve.hpp cpp/field.hpp
            cpp/batch_inv.hpp cpp/windowed_g_table.hpp
            cpp/ecrecover_pipeline.hpp cpp/ecdsa.hpp
    CABI    c-abi/c_secp256k1.cpp
    METAL_DRIVER gpu/metal/secp256k1_first_party_driver.mm
    METAL_HEADERS gpu/metal/secp256k1_driver.h
)

target_include_directories(secp256k1_cpu PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
target_include_directories(secp256k1 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

# v0.63 Stage A — Montgomery batch inversion GPU drivers. Separate libraries
# because kinet_add_algorithm only takes a single GPU-driver slot per backend.

# ---- Metal --------------------------------------------------------------
if(APPLE AND CRYPTO_ENABLE_METAL)
    add_library(secp256k1_batch_inv_metal STATIC
        gpu/metal/secp256k1_batch_inv_driver.mm)
    target_include_directories(secp256k1_batch_inv_metal PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    )
    target_compile_features(secp256k1_batch_inv_metal PUBLIC cxx_std_20)
    set_target_properties(secp256k1_batch_inv_metal PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        COMPILE_FLAGS "-fobjc-arc"
    )
    target_link_libraries(secp256k1_batch_inv_metal PUBLIC
        "-framework Metal"
        "-framework Foundation"
    )
endif()

# ---- CUDA ---------------------------------------------------------------
# Two-source library: kernel TU + driver TU. When CRYPTO_ENABLE_CUDA is OFF
# the .cu files compile as plain C++ and emit NOTIMPL stubs (sentinel -100)
# so the umbrella library still links on macOS / non-CUDA hosts. CI runs on
# hanzo-build-linux-amd64 with nvcc to build the real device path.
set(_SECP256K1_BATCH_INV_CUDA_SOURCES
    gpu/cuda/secp256k1_batch_inv.cu
    gpu/cuda/secp256k1_batch_inv_driver.cu
)
if(CRYPTO_ENABLE_CUDA)
    add_library(secp256k1_batch_inv_cuda STATIC
        ${_SECP256K1_BATCH_INV_CUDA_SOURCES})
    set_target_properties(secp256k1_batch_inv_cuda PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        CUDA_SEPARABLE_COMPILATION ON
        CUDA_ARCHITECTURES "75"
    )
    target_include_directories(secp256k1_batch_inv_cuda PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    )
else()
    foreach(_src ${_SECP256K1_BATCH_INV_CUDA_SOURCES})
        set_source_files_properties(${_src} PROPERTIES LANGUAGE CXX)
    endforeach()
    add_library(secp256k1_batch_inv_cuda STATIC
        ${_SECP256K1_BATCH_INV_CUDA_SOURCES})
    target_include_directories(secp256k1_batch_inv_cuda PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    )
    target_compile_features(secp256k1_batch_inv_cuda PUBLIC cxx_std_20)
    set_target_properties(secp256k1_batch_inv_cuda PROPERTIES
        POSITION_INDEPENDENT_CODE ON
    )
endif()

# ---- WGSL ---------------------------------------------------------------
# Single-source: the host-side dispatch wrapper. Real WebGPU dispatch is
# enabled by CRYPTO_HAS_DAWN at compile-time (set by CI when Dawn /
# wgpu-native is available). Otherwise the entry point returns NOTIMPL.
add_library(secp256k1_batch_inv_wgsl STATIC
    gpu/wgsl/secp256k1_batch_inv_driver.cpp)
target_include_directories(secp256k1_batch_inv_wgsl PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
target_compile_features(secp256k1_batch_inv_wgsl PUBLIC cxx_std_20)
set_target_properties(secp256k1_batch_inv_wgsl PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

# Note: test executables (batch_inv_cuda_test / batch_inv_wgsl_test) are
# registered in the root CMakeLists.txt next to the other secp256k1 tests,
# matching project convention.

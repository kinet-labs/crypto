# =============================================================================
# gpukit -- common GPU kernel-pattern library
# =============================================================================
#
# Layout (one set per primitive):
#   include/kinet/gpukit/<prim>.h       public C ABI
#   cpp/cpu_reference/<prim>.cpp      CPU reference (byte-equal target)
#   gpu/metal/<prim>.metal            Metal kernel
#   gpu/metal/<prim>_driver.mm        Metal host driver
#   gpu/cuda/<prim>.cu                CUDA kernel + host wrapper
#   gpu/wgsl/<prim>.wgsl              WGSL kernel
#   gpu/wgsl/<prim>_driver.cpp        Dawn / wgpu-native host driver
#   test/<prim>_test.cpp              determinism harness
#
# Brand-neutral surface throughout. Path-level kinet/ scope is the only place
# the brand appears.
# =============================================================================

# ---- Libraries -------------------------------------------------------------

set(_GPUKIT_CPU_SOURCES
    cpp/cpu_reference/gpukit.cpp
    cpp/cpu_reference/prefix_sum.cpp
    cpp/cpu_reference/compaction.cpp
    cpp/cpu_reference/radix_sort.cpp
    cpp/cpu_reference/batch_inversion.cpp
    cpp/cpu_reference/merkle_compose.cpp
    cpp/cpu_reference/transcript_root.cpp
    cpp/cpu_reference/ntt.cpp
)

add_library(gpukit_cpu STATIC ${_GPUKIT_CPU_SOURCES})
target_include_directories(gpukit_cpu PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
target_compile_features(gpukit_cpu PUBLIC cxx_std_20)
set_target_properties(gpukit_cpu PROPERTIES POSITION_INDEPENDENT_CODE ON)
# CPU references for merkle_compose / transcript_root use Keccak-256 from the
# sibling keccak module.
target_link_libraries(gpukit_cpu PUBLIC keccak_cpu)
add_library(kinet::gpukit_cpu ALIAS gpukit_cpu)

# ---- Metal driver ----------------------------------------------------------

if(APPLE AND KINET_CRYPTO_ENABLE_METAL)
    set(_GPUKIT_METAL_SOURCES
        gpu/metal/prefix_sum_driver.mm
        gpu/metal/compaction_driver.mm
        gpu/metal/radix_sort_driver.mm
        gpu/metal/batch_inversion_driver.mm
        gpu/metal/merkle_compose_driver.mm
        gpu/metal/transcript_root_driver.mm
        gpu/metal/ntt_driver.mm
    )
    add_library(gpukit_metal STATIC ${_GPUKIT_METAL_SOURCES})
    target_include_directories(gpukit_metal PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    )
    target_compile_features(gpukit_metal PUBLIC cxx_std_20)
    set_target_properties(gpukit_metal PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        COMPILE_FLAGS "-fobjc-arc"
    )
    target_link_libraries(gpukit_metal
        PUBLIC gpukit_cpu
        PUBLIC "-framework Metal" "-framework Foundation"
    )
    add_library(kinet::gpukit_metal ALIAS gpukit_metal)

    # Compile the Metal kernels into a single metallib named libgpukit.metallib.
    find_program(_GPUKIT_XCRUN xcrun)
    if(_GPUKIT_XCRUN)
        set(_GPUKIT_METAL_KERNELS
            ${CMAKE_CURRENT_SOURCE_DIR}/gpu/metal/prefix_sum.metal
            ${CMAKE_CURRENT_SOURCE_DIR}/gpu/metal/compaction.metal
            ${CMAKE_CURRENT_SOURCE_DIR}/gpu/metal/radix_sort.metal
            ${CMAKE_CURRENT_SOURCE_DIR}/gpu/metal/batch_inversion.metal
            ${CMAKE_CURRENT_SOURCE_DIR}/gpu/metal/merkle_compose.metal
            ${CMAKE_CURRENT_SOURCE_DIR}/gpu/metal/transcript_root.metal
            ${CMAKE_CURRENT_SOURCE_DIR}/gpu/metal/ntt.metal
        )
        set(_GPUKIT_AIR_FILES "")
        foreach(_kn ${_GPUKIT_METAL_KERNELS})
            get_filename_component(_kn_name ${_kn} NAME_WE)
            set(_air ${CMAKE_BINARY_DIR}/gpukit_${_kn_name}.air)
            add_custom_command(
                OUTPUT ${_air}
                COMMAND ${_GPUKIT_XCRUN} -sdk macosx metal -c ${_kn} -o ${_air}
                DEPENDS ${_kn}
                COMMENT "metal -c ${_kn_name}.metal"
            )
            list(APPEND _GPUKIT_AIR_FILES ${_air})
        endforeach()
        set(_GPUKIT_METALLIB ${CMAKE_BINARY_DIR}/libgpukit.metallib)
        add_custom_command(
            OUTPUT ${_GPUKIT_METALLIB}
            COMMAND ${_GPUKIT_XCRUN} -sdk macosx metallib ${_GPUKIT_AIR_FILES} -o ${_GPUKIT_METALLIB}
            DEPENDS ${_GPUKIT_AIR_FILES}
            COMMENT "metallib -> libgpukit.metallib"
        )
        add_custom_target(gpukit_metallib ALL DEPENDS ${_GPUKIT_METALLIB})
        set_property(GLOBAL PROPERTY GPUKIT_METALLIB_PATH ${_GPUKIT_METALLIB})
    endif()
endif()

# ---- CUDA driver -----------------------------------------------------------

if(KINET_CRYPTO_ENABLE_CUDA OR KINET_GPUKIT_ENABLE_CUDA)
    set(_GPUKIT_CUDA_SOURCES
        gpu/cuda/prefix_sum.cu
        gpu/cuda/compaction.cu
        gpu/cuda/radix_sort.cu
        gpu/cuda/batch_inversion.cu
        gpu/cuda/merkle_compose.cu
        gpu/cuda/transcript_root.cu
        gpu/cuda/ntt.cu
    )
    add_library(gpukit_cuda STATIC ${_GPUKIT_CUDA_SOURCES})
    set_target_properties(gpukit_cuda PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        CUDA_SEPARABLE_COMPILATION ON
    )
    target_include_directories(gpukit_cuda PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    )
    target_link_libraries(gpukit_cuda PUBLIC gpukit_cpu)
    add_library(kinet::gpukit_cuda ALIAS gpukit_cuda)
else()
    # On Apple/no-CUDA hosts we still need the symbols. The .cu files are
    # written so they emit NOTIMPL stubs when __CUDACC__/KINET_GPUKIT_HAS_CUDA is
    # not defined; compile them as regular C++ TUs.
    set(_GPUKIT_CUDA_STUBS
        gpu/cuda/prefix_sum.cu
        gpu/cuda/compaction.cu
        gpu/cuda/radix_sort.cu
        gpu/cuda/batch_inversion.cu
        gpu/cuda/merkle_compose.cu
        gpu/cuda/transcript_root.cu
        gpu/cuda/ntt.cu
    )
    foreach(_src ${_GPUKIT_CUDA_STUBS})
        set_source_files_properties(${_src} PROPERTIES LANGUAGE CXX)
    endforeach()
    add_library(gpukit_cuda STATIC ${_GPUKIT_CUDA_STUBS})
    target_include_directories(gpukit_cuda PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    )
    target_compile_features(gpukit_cuda PUBLIC cxx_std_20)
    set_target_properties(gpukit_cuda PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_link_libraries(gpukit_cuda PUBLIC gpukit_cpu)
    add_library(kinet::gpukit_cuda ALIAS gpukit_cuda)
endif()

# ---- WGSL driver -----------------------------------------------------------

if(KINET_CRYPTO_ENABLE_WGSL OR KINET_GPUKIT_ENABLE_WGSL)
    set(_GPUKIT_WGSL_SOURCES
        gpu/wgsl/prefix_sum_driver.cpp
        gpu/wgsl/compaction_driver.cpp
        gpu/wgsl/radix_sort_driver.cpp
        gpu/wgsl/batch_inversion_driver.cpp
        gpu/wgsl/merkle_compose_driver.cpp
        gpu/wgsl/transcript_root_driver.cpp
        gpu/wgsl/ntt_driver.cpp
    )
    add_library(gpukit_wgsl STATIC ${_GPUKIT_WGSL_SOURCES})
    target_include_directories(gpukit_wgsl PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    )
    target_compile_features(gpukit_wgsl PUBLIC cxx_std_20)
    set_target_properties(gpukit_wgsl PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_link_libraries(gpukit_wgsl PUBLIC gpukit_cpu)
    add_library(kinet::gpukit_wgsl ALIAS gpukit_wgsl)
endif()

# ---- Umbrella --------------------------------------------------------------

add_library(gpukit INTERFACE)
target_link_libraries(gpukit INTERFACE gpukit_cpu)
if(TARGET gpukit_metal)
    target_link_libraries(gpukit INTERFACE gpukit_metal)
endif()
if(TARGET gpukit_cuda)
    target_link_libraries(gpukit INTERFACE gpukit_cuda)
endif()
if(TARGET gpukit_wgsl)
    target_link_libraries(gpukit INTERFACE gpukit_wgsl)
endif()
add_library(kinet::gpukit ALIAS gpukit)

# ---- Tests -----------------------------------------------------------------

if(KINET_CRYPTO_BUILD_TESTS)
    enable_testing()
    set(_GPUKIT_TESTS
        prefix_sum
        compaction
        radix_sort
        batch_inversion
        merkle_compose
        transcript_root
        ntt
    )
    foreach(_t ${_GPUKIT_TESTS})
        add_executable(gpukit_${_t}_test test/${_t}_test.cpp)
        target_link_libraries(gpukit_${_t}_test PRIVATE gpukit)
        add_test(NAME gpukit-${_t}-test COMMAND gpukit_${_t}_test)
        if(TARGET gpukit_metallib)
            add_dependencies(gpukit_${_t}_test gpukit_metallib)
            set_property(TEST gpukit-${_t}-test PROPERTY
                ENVIRONMENT "GPUKIT_METALLIB=${CMAKE_BINARY_DIR}/libgpukit.metallib")
        endif()
    endforeach()
    add_custom_target(gpukit-tests
        DEPENDS
            gpukit_prefix_sum_test
            gpukit_compaction_test
            gpukit_radix_sort_test
            gpukit_batch_inversion_test
            gpukit_merkle_compose_test
            gpukit_transcript_root_test
            gpukit_ntt_test
    )
endif()

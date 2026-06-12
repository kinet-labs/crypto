# =============================================================================
# KinetAlgorithm.cmake - per-algorithm helper for kinet-labs/crypto
# =============================================================================
#
# Usage in <alg>/CMakeLists.txt:
#
#   include(KinetAlgorithm)
#   kinet_add_algorithm(
#       NAME    keccak
#       SOURCES cpp/keccak.c cpp/keccak.cpp     # mandatory CPU sources
#       HEADERS cpp/keccak.h cpp/keccak.hpp     # public C/C++ headers
#       CABI    c-abi/c_keccak.cpp              # extern "C" shim
#   )
#
# The macro builds:
#   lib<NAME>_cpu.a            -> CPU-only static lib
#   lib<NAME>.a                -> umbrella static lib that links the above plus
#                                 any optional GPU drivers (Metal/CUDA/WGSL)
#
# Targets are exported as kinet::<name>_cpu and kinet::<name>.
#
# =============================================================================

include_guard(GLOBAL)

function(kinet_add_algorithm)
    set(options "")
    set(oneValue NAME)
    set(multiValue SOURCES HEADERS CABI METAL_DRIVER METAL_HEADERS CUDA_SOURCES WGSL_DRIVER)
    cmake_parse_arguments(LA "${options}" "${oneValue}" "${multiValue}" ${ARGN})

    if(NOT LA_NAME)
        message(FATAL_ERROR "kinet_add_algorithm: NAME is required")
    endif()

    set(_target_cpu "${LA_NAME}_cpu")
    set(_target_all "${LA_NAME}")

    # ---- CPU-only static lib --------------------------------------------------
    if(LA_SOURCES)
        add_library(${_target_cpu} STATIC ${LA_SOURCES})
    else()
        add_library(${_target_cpu} STATIC)
    endif()
    target_include_directories(${_target_cpu}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cpp>
            $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/c-abi>
            $<INSTALL_INTERFACE:include>
    )
    target_compile_features(${_target_cpu} PUBLIC cxx_std_20)
    set_target_properties(${_target_cpu} PROPERTIES POSITION_INDEPENDENT_CODE ON)
    add_library(kinet::${_target_cpu} ALIAS ${_target_cpu})

    # ---- Optional Metal driver (.mm + .h) ------------------------------------
    set(_metal_target "")
    if(APPLE AND CRYPTO_ENABLE_METAL AND LA_METAL_DRIVER)
        set(_metal_target "${LA_NAME}_metal")
        add_library(${_metal_target} STATIC ${LA_METAL_DRIVER})
        target_include_directories(${_metal_target}
            PUBLIC
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/gpu/metal>
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cpp>
                $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/c-abi>
        )
        target_compile_features(${_metal_target} PUBLIC cxx_std_20)
        set_target_properties(${_metal_target} PROPERTIES
            POSITION_INDEPENDENT_CODE ON
            COMPILE_FLAGS "-fobjc-arc"
        )
        target_link_libraries(${_metal_target} PUBLIC
            "-framework Metal"
            "-framework Foundation"
        )
        add_library(kinet::${_metal_target} ALIAS ${_metal_target})
    endif()

    # ---- Optional CUDA driver -------------------------------------------------
    set(_cuda_target "")
    if(CRYPTO_ENABLE_CUDA AND LA_CUDA_SOURCES)
        set(_cuda_target "${LA_NAME}_cuda")
        add_library(${_cuda_target} STATIC ${LA_CUDA_SOURCES})
        target_include_directories(${_cuda_target}
            PUBLIC
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/gpu/cuda>
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cpp>
                $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/c-abi>
        )
        set_target_properties(${_cuda_target} PROPERTIES
            POSITION_INDEPENDENT_CODE ON
            CUDA_SEPARABLE_COMPILATION ON
        )
        add_library(kinet::${_cuda_target} ALIAS ${_cuda_target})
    endif()

    # ---- Optional WGSL driver -------------------------------------------------
    set(_wgsl_target "")
    if(CRYPTO_ENABLE_WGSL AND LA_WGSL_DRIVER)
        set(_wgsl_target "${LA_NAME}_wgsl")
        add_library(${_wgsl_target} STATIC ${LA_WGSL_DRIVER})
        target_include_directories(${_wgsl_target}
            PUBLIC
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/gpu/wgsl>
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cpp>
                $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/c-abi>
        )
        target_compile_features(${_wgsl_target} PUBLIC cxx_std_20)
        set_target_properties(${_wgsl_target} PROPERTIES POSITION_INDEPENDENT_CODE ON)
        add_library(kinet::${_wgsl_target} ALIAS ${_wgsl_target})
    endif()

    # ---- C-ABI shim + umbrella lib -------------------------------------------
    if(LA_CABI)
        add_library(${_target_all} STATIC ${LA_CABI})
    else()
        add_library(${_target_all} STATIC)
    endif()
    target_include_directories(${_target_all}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/c-abi>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cpp>
            $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/c-abi>
    )
    target_compile_features(${_target_all} PUBLIC cxx_std_20)
    set_target_properties(${_target_all} PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_link_libraries(${_target_all} PUBLIC ${_target_cpu})
    if(_metal_target)
        target_link_libraries(${_target_all} PUBLIC ${_metal_target})
    endif()
    if(_cuda_target)
        target_link_libraries(${_target_all} PUBLIC ${_cuda_target})
    endif()
    if(_wgsl_target)
        target_link_libraries(${_target_all} PUBLIC ${_wgsl_target})
    endif()
    add_library(kinet::${_target_all} ALIAS ${_target_all})

    set_property(GLOBAL APPEND PROPERTY CRYPTO_ALGORITHMS ${LA_NAME})
endfunction()

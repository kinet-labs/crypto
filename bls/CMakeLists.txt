# bls - BLS12-381 (consensus signatures + EIP-2537 precompiles)
#
# This file works in two modes:
#   1. As a subdirectory of the parent crypto/ project (default; uses kinet_add_algorithm).
#   2. Standalone for the Stage 1 Fp-tower test:
#        cmake -S /Users/z/work/kinet-labs/crypto/bls -B build -DCMAKE_BUILD_TYPE=Release
#        cmake --build build --target bls-fp-tower-test
#        ctest --test-dir build -R bls-fp-tower-test --output-on-failure

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    cmake_minimum_required(VERSION 3.20)
    project(bls-stage1 VERSION 1.0.0 LANGUAGES CXX OBJCXX)
    set(BLS_STANDALONE TRUE)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_OBJCXX_STANDARD 17)
    if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Release)
    endif()
    enable_testing()
endif()

if(NOT BLS_STANDALONE)
    include(KinetAlgorithm)
    kinet_add_algorithm(
        NAME    bls
        SOURCES c-abi/c_bls.cpp
        HEADERS cpp/bls.hpp
        CABI    c-abi/c_bls.cpp
        METAL_DRIVER gpu/metal/bls_driver.mm
        METAL_HEADERS gpu/metal/bls_driver.h
    )
endif()

# =============================================================================
# Stage 1 — Fp2/Fp6/Fp12 tower arithmetic on Metal, byte-equal to blst.
#
# Builds:
#   1. bls_fp_tower_oracle  (host C++; links blst; emits vectors_fp_tower.h)
#   2. bls_fp_tower.metallib (compiles three .metal files into one library)
#   3. bls_fp_tower_test     (Obj-C++; loads metallib; byte-compares output)
#
# blst is the BUILD-TIME oracle. It is NOT linked into the production library;
# only into the test oracle binary that emits the expected-output header.
# =============================================================================

if(APPLE)
    set(BLST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../cevm/build/deps/src/blst")
    if(EXISTS "${BLST_DIR}/libblst.a")
        find_program(XCRUN xcrun)
        if(XCRUN)

            add_library(bls_stage1_blst STATIC IMPORTED)
            set_target_properties(bls_stage1_blst PROPERTIES
                IMPORTED_LOCATION "${BLST_DIR}/libblst.a"
                INTERFACE_INCLUDE_DIRECTORIES "${BLST_DIR}/bindings")

            # 1) Oracle binary
            add_executable(bls_fp_tower_oracle test/bls_fp_tower_oracle.cpp)
            target_link_libraries(bls_fp_tower_oracle PRIVATE bls_stage1_blst)
            target_compile_options(bls_fp_tower_oracle PRIVATE -O3)

            set(BLS_VEC_HEADER "${CMAKE_CURRENT_BINARY_DIR}/vectors_fp_tower.h")
            add_custom_command(
                OUTPUT "${BLS_VEC_HEADER}"
                COMMAND $<TARGET_FILE:bls_fp_tower_oracle> "${BLS_VEC_HEADER}"
                DEPENDS bls_fp_tower_oracle
                COMMENT "Generating Fp-tower test vectors via blst")
            add_custom_target(bls_fp_tower_vectors DEPENDS "${BLS_VEC_HEADER}")

            # 2) Metal library compilation
            set(BLS_METAL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/gpu/metal")
            set(BLS_METAL_FILES
                "${BLS_METAL_DIR}/bls_fp2.metal"
                "${BLS_METAL_DIR}/bls_fp6.metal"
                "${BLS_METAL_DIR}/bls_fp12.metal")

            set(BLS_AIR_FILES)
            foreach(SRC ${BLS_METAL_FILES})
                get_filename_component(STEM ${SRC} NAME_WE)
                set(AIR "${CMAKE_CURRENT_BINARY_DIR}/${STEM}.air")
                list(APPEND BLS_AIR_FILES "${AIR}")
                add_custom_command(
                    OUTPUT "${AIR}"
                    COMMAND ${XCRUN} -sdk macosx metal -O3 -ffast-math
                            -I "${BLS_METAL_DIR}"
                            -c "${SRC}" -o "${AIR}"
                    DEPENDS "${SRC}"
                            "${BLS_METAL_DIR}/bls_fp_ops.h.metal"
                    COMMENT "metal -c ${STEM}.metal")
            endforeach()

            set(BLS_METALLIB "${CMAKE_CURRENT_BINARY_DIR}/bls_fp_tower.metallib")
            add_custom_command(
                OUTPUT "${BLS_METALLIB}"
                COMMAND ${XCRUN} -sdk macosx metallib ${BLS_AIR_FILES}
                        -o "${BLS_METALLIB}"
                DEPENDS ${BLS_AIR_FILES}
                COMMENT "metallib bls_fp_tower.metallib")
            add_custom_target(bls_fp_tower_metallib DEPENDS "${BLS_METALLIB}")

            # 3) Test binary
            add_executable(bls_fp_tower_test test/bls_fp_tower_test.mm)
            target_include_directories(bls_fp_tower_test
                PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
            target_compile_options(bls_fp_tower_test PRIVATE -O3 -fobjc-arc)
            add_dependencies(bls_fp_tower_test
                bls_fp_tower_vectors bls_fp_tower_metallib)
            target_link_libraries(bls_fp_tower_test PRIVATE
                "-framework Metal" "-framework Foundation")

            # CTest entry
            if(NOT BLS_STANDALONE)
                # In integrated builds, parent should have already enable_testing()'d.
            endif()
            add_test(NAME bls-fp-tower-test
                COMMAND bls_fp_tower_test "${BLS_METALLIB}")

            # Build target with the same name as the CTest entry — `cmake --build .
            # --target bls-fp-tower-test` builds everything the test needs.
            add_custom_target(bls-fp-tower-test
                DEPENDS bls_fp_tower_test bls_fp_tower_metallib bls_fp_tower_vectors)

            message(STATUS "[bls-stage1] enabled (Metal)")
            message(STATUS "[bls-stage1]   blst:     ${BLST_DIR}/libblst.a")
            message(STATUS "[bls-stage1]   metallib: ${BLS_METALLIB}")
            message(STATUS "[bls-stage1]   vectors:  ${BLS_VEC_HEADER}")

            # =========================================================
            # Stage 2 — G2 affine/Jacobian + optimal-ate Miller loop.
            # =========================================================

            # ---- G2 oracle + metallib + test ----
            add_executable(bls_g2_oracle test/bls_g2_oracle.cpp)
            target_link_libraries(bls_g2_oracle PRIVATE bls_stage1_blst)
            target_compile_options(bls_g2_oracle PRIVATE -O3)

            set(BLS_G2_VEC "${CMAKE_CURRENT_BINARY_DIR}/vectors_g2.h")
            add_custom_command(
                OUTPUT "${BLS_G2_VEC}"
                COMMAND $<TARGET_FILE:bls_g2_oracle> "${BLS_G2_VEC}"
                DEPENDS bls_g2_oracle
                COMMENT "Generating G2 test vectors via blst")
            add_custom_target(bls_g2_vectors DEPENDS "${BLS_G2_VEC}")

            set(BLS_G2_AIR "${CMAKE_CURRENT_BINARY_DIR}/bls_g2.air")
            add_custom_command(
                OUTPUT "${BLS_G2_AIR}"
                COMMAND ${XCRUN} -sdk macosx metal -O3 -ffast-math
                        -I "${BLS_METAL_DIR}"
                        -c "${BLS_METAL_DIR}/bls_g2.metal" -o "${BLS_G2_AIR}"
                DEPENDS "${BLS_METAL_DIR}/bls_g2.metal"
                        "${BLS_METAL_DIR}/bls_fp2.metal"
                        "${BLS_METAL_DIR}/bls_fp_ops.h.metal"
                COMMENT "metal -c bls_g2.metal")

            set(BLS_G2_METALLIB "${CMAKE_CURRENT_BINARY_DIR}/bls_g2.metallib")
            add_custom_command(
                OUTPUT "${BLS_G2_METALLIB}"
                COMMAND ${XCRUN} -sdk macosx metallib "${BLS_G2_AIR}"
                        -o "${BLS_G2_METALLIB}"
                DEPENDS "${BLS_G2_AIR}"
                COMMENT "metallib bls_g2.metallib")
            add_custom_target(bls_g2_metallib DEPENDS "${BLS_G2_METALLIB}")

            add_executable(bls_g2_test test/bls_g2_test.mm)
            target_include_directories(bls_g2_test
                PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
            target_compile_options(bls_g2_test PRIVATE -O3 -fobjc-arc)
            add_dependencies(bls_g2_test bls_g2_vectors bls_g2_metallib)
            target_link_libraries(bls_g2_test PRIVATE
                "-framework Metal" "-framework Foundation")

            add_test(NAME bls-g2-test
                COMMAND bls_g2_test "${BLS_G2_METALLIB}")

            add_custom_target(bls-g2-test
                DEPENDS bls_g2_test bls_g2_metallib bls_g2_vectors)

            # ---- Miller-loop oracle + metallib + test ----
            add_executable(bls_miller_oracle test/bls_miller_oracle.cpp)
            target_link_libraries(bls_miller_oracle PRIVATE bls_stage1_blst)
            target_compile_options(bls_miller_oracle PRIVATE -O3)

            set(BLS_MILLER_VEC "${CMAKE_CURRENT_BINARY_DIR}/vectors_miller.h")
            add_custom_command(
                OUTPUT "${BLS_MILLER_VEC}"
                COMMAND $<TARGET_FILE:bls_miller_oracle> "${BLS_MILLER_VEC}"
                DEPENDS bls_miller_oracle
                COMMENT "Generating Miller-loop test vectors via blst")
            add_custom_target(bls_miller_vectors DEPENDS "${BLS_MILLER_VEC}")

            set(BLS_MILLER_AIR "${CMAKE_CURRENT_BINARY_DIR}/bls_miller.air")
            add_custom_command(
                OUTPUT "${BLS_MILLER_AIR}"
                COMMAND ${XCRUN} -sdk macosx metal -O3 -ffast-math
                        -I "${BLS_METAL_DIR}"
                        -c "${BLS_METAL_DIR}/bls_miller.metal"
                        -o "${BLS_MILLER_AIR}"
                DEPENDS "${BLS_METAL_DIR}/bls_miller.metal"
                        "${BLS_METAL_DIR}/bls_g2.metal"
                        "${BLS_METAL_DIR}/bls_fp12.metal"
                        "${BLS_METAL_DIR}/bls_fp6.metal"
                        "${BLS_METAL_DIR}/bls_fp2.metal"
                        "${BLS_METAL_DIR}/bls_fp_ops.h.metal"
                COMMENT "metal -c bls_miller.metal")

            set(BLS_MILLER_METALLIB "${CMAKE_CURRENT_BINARY_DIR}/bls_miller.metallib")
            add_custom_command(
                OUTPUT "${BLS_MILLER_METALLIB}"
                COMMAND ${XCRUN} -sdk macosx metallib "${BLS_MILLER_AIR}"
                        -o "${BLS_MILLER_METALLIB}"
                DEPENDS "${BLS_MILLER_AIR}"
                COMMENT "metallib bls_miller.metallib")
            add_custom_target(bls_miller_metallib DEPENDS "${BLS_MILLER_METALLIB}")

            add_executable(bls_miller_test test/bls_miller_test.mm)
            target_include_directories(bls_miller_test
                PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
            target_compile_options(bls_miller_test PRIVATE -O3 -fobjc-arc)
            add_dependencies(bls_miller_test bls_miller_vectors bls_miller_metallib)
            target_link_libraries(bls_miller_test PRIVATE
                "-framework Metal" "-framework Foundation")

            add_test(NAME bls-miller-test
                COMMAND bls_miller_test "${BLS_MILLER_METALLIB}")

            add_custom_target(bls-miller-test
                DEPENDS bls_miller_test bls_miller_metallib bls_miller_vectors)

            message(STATUS "[bls-stage2] enabled (Metal)")
            message(STATUS "[bls-stage2]   g2 metallib:     ${BLS_G2_METALLIB}")
            message(STATUS "[bls-stage2]   miller metallib: ${BLS_MILLER_METALLIB}")

            # =========================================================
            # Stage 3 — final_exp + full pairing on Metal.
            # =========================================================

            # ---- final_exp oracle + metallib + test ----
            add_executable(bls_final_exp_oracle test/bls_final_exp_oracle.cpp)
            target_link_libraries(bls_final_exp_oracle PRIVATE bls_stage1_blst)
            target_compile_options(bls_final_exp_oracle PRIVATE -O3)

            set(BLS_FE_VEC "${CMAKE_CURRENT_BINARY_DIR}/vectors_final_exp.h")
            add_custom_command(
                OUTPUT "${BLS_FE_VEC}"
                COMMAND $<TARGET_FILE:bls_final_exp_oracle> "${BLS_FE_VEC}"
                DEPENDS bls_final_exp_oracle
                COMMENT "Generating final_exp test vectors via blst")
            add_custom_target(bls_final_exp_vectors DEPENDS "${BLS_FE_VEC}")

            set(BLS_FE_AIR "${CMAKE_CURRENT_BINARY_DIR}/bls_final_exp.air")
            add_custom_command(
                OUTPUT "${BLS_FE_AIR}"
                COMMAND ${XCRUN} -sdk macosx metal -O3 -ffast-math
                        -I "${BLS_METAL_DIR}"
                        -c "${BLS_METAL_DIR}/bls_final_exp.metal"
                        -o "${BLS_FE_AIR}"
                DEPENDS "${BLS_METAL_DIR}/bls_final_exp.metal"
                        "${BLS_METAL_DIR}/bls_fp12.metal"
                        "${BLS_METAL_DIR}/bls_fp6.metal"
                        "${BLS_METAL_DIR}/bls_fp2.metal"
                        "${BLS_METAL_DIR}/bls_fp_ops.h.metal"
                COMMENT "metal -c bls_final_exp.metal")

            set(BLS_FE_METALLIB "${CMAKE_CURRENT_BINARY_DIR}/bls_final_exp.metallib")
            add_custom_command(
                OUTPUT "${BLS_FE_METALLIB}"
                COMMAND ${XCRUN} -sdk macosx metallib "${BLS_FE_AIR}"
                        -o "${BLS_FE_METALLIB}"
                DEPENDS "${BLS_FE_AIR}"
                COMMENT "metallib bls_final_exp.metallib")
            add_custom_target(bls_final_exp_metallib DEPENDS "${BLS_FE_METALLIB}")

            add_executable(bls_final_exp_test test/bls_final_exp_test.mm)
            target_include_directories(bls_final_exp_test
                PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
            target_compile_options(bls_final_exp_test PRIVATE -O3 -fobjc-arc)
            add_dependencies(bls_final_exp_test
                bls_final_exp_vectors bls_final_exp_metallib)
            target_link_libraries(bls_final_exp_test PRIVATE
                "-framework Metal" "-framework Foundation")

            add_test(NAME bls-final-exp-test
                COMMAND bls_final_exp_test "${BLS_FE_METALLIB}")

            add_custom_target(bls-final-exp-test
                DEPENDS bls_final_exp_test bls_final_exp_metallib
                        bls_final_exp_vectors)

            # ---- Pairing: combined metallib (miller + final_exp + pairing) ----
            # The pairing test driver chains Miller-loop and final_exp kernels
            # in a single command queue, so all kernels live in one metallib.
            set(BLS_PAIR_METAL_FILES
                "${BLS_METAL_DIR}/bls_miller.metal"
                "${BLS_METAL_DIR}/bls_final_exp.metal"
                "${BLS_METAL_DIR}/bls_pairing.metal")

            set(BLS_PAIR_AIR_FILES)
            foreach(SRC ${BLS_PAIR_METAL_FILES})
                get_filename_component(STEM ${SRC} NAME_WE)
                set(AIR "${CMAKE_CURRENT_BINARY_DIR}/${STEM}_pair.air")
                list(APPEND BLS_PAIR_AIR_FILES "${AIR}")
                add_custom_command(
                    OUTPUT "${AIR}"
                    COMMAND ${XCRUN} -sdk macosx metal -O3 -ffast-math
                            -I "${BLS_METAL_DIR}"
                            -c "${SRC}" -o "${AIR}"
                    DEPENDS "${SRC}"
                            "${BLS_METAL_DIR}/bls_g2.metal"
                            "${BLS_METAL_DIR}/bls_fp12.metal"
                            "${BLS_METAL_DIR}/bls_fp6.metal"
                            "${BLS_METAL_DIR}/bls_fp2.metal"
                            "${BLS_METAL_DIR}/bls_fp_ops.h.metal"
                    COMMENT "metal -c ${STEM}.metal (pair build)")
            endforeach()

            set(BLS_PAIR_METALLIB "${CMAKE_CURRENT_BINARY_DIR}/bls_pairing.metallib")
            add_custom_command(
                OUTPUT "${BLS_PAIR_METALLIB}"
                COMMAND ${XCRUN} -sdk macosx metallib ${BLS_PAIR_AIR_FILES}
                        -o "${BLS_PAIR_METALLIB}"
                DEPENDS ${BLS_PAIR_AIR_FILES}
                COMMENT "metallib bls_pairing.metallib")
            add_custom_target(bls_pairing_metallib DEPENDS "${BLS_PAIR_METALLIB}")

            # ---- pairing oracle + test ----
            add_executable(bls_pairing_oracle test/bls_pairing_oracle.cpp)
            target_link_libraries(bls_pairing_oracle PRIVATE bls_stage1_blst)
            target_compile_options(bls_pairing_oracle PRIVATE -O3)

            set(BLS_PAIR_VEC "${CMAKE_CURRENT_BINARY_DIR}/vectors_pairing.h")
            add_custom_command(
                OUTPUT "${BLS_PAIR_VEC}"
                COMMAND $<TARGET_FILE:bls_pairing_oracle> "${BLS_PAIR_VEC}"
                DEPENDS bls_pairing_oracle
                COMMENT "Generating pairing test vectors via blst")
            add_custom_target(bls_pairing_vectors DEPENDS "${BLS_PAIR_VEC}")

            add_executable(bls_pairing_test test/bls_pairing_test.mm)
            target_include_directories(bls_pairing_test
                PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
            target_compile_options(bls_pairing_test PRIVATE -O3 -fobjc-arc)
            add_dependencies(bls_pairing_test
                bls_pairing_vectors bls_pairing_metallib)
            target_link_libraries(bls_pairing_test PRIVATE
                "-framework Metal" "-framework Foundation")

            add_test(NAME bls-pairing-test
                COMMAND bls_pairing_test "${BLS_PAIR_METALLIB}")

            add_custom_target(bls-pairing-test
                DEPENDS bls_pairing_test bls_pairing_metallib
                        bls_pairing_vectors)

            message(STATUS "[bls-stage3] enabled (Metal)")
            message(STATUS "[bls-stage3]   final_exp metallib: ${BLS_FE_METALLIB}")
            message(STATUS "[bls-stage3]   pairing metallib:   ${BLS_PAIR_METALLIB}")

            # =========================================================
            # Stage 4 — CUDA + WGSL parity ports of Stages 1-3.
            #   * CUDA: build-only on Apple (gated for Linux+CUDA CI).
            #   * WGSL: byte-equal to CPU oracle on Apple via wgpu-native.
            #   * subgroup rejection vectors via blst predicate.
            # =========================================================

            # ---- Subgroup rejection vector oracle + test ----
            add_executable(bls_subgroup_oracle test/bls_subgroup_oracle.cpp)
            target_link_libraries(bls_subgroup_oracle PRIVATE bls_stage1_blst)
            target_compile_options(bls_subgroup_oracle PRIVATE -O3)

            set(BLS_SUBG_VEC "${CMAKE_CURRENT_BINARY_DIR}/vectors_subgroup.h")
            add_custom_command(
                OUTPUT "${BLS_SUBG_VEC}"
                COMMAND $<TARGET_FILE:bls_subgroup_oracle> "${BLS_SUBG_VEC}"
                DEPENDS bls_subgroup_oracle
                COMMENT "Generating subgroup test vectors via blst")
            add_custom_target(bls_subgroup_vectors DEPENDS "${BLS_SUBG_VEC}")

            add_executable(bls_subgroup_test test/bls_subgroup_test.cpp)
            target_include_directories(bls_subgroup_test
                PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
            target_compile_options(bls_subgroup_test PRIVATE -O3)
            target_link_libraries(bls_subgroup_test PRIVATE bls_stage1_blst)
            add_dependencies(bls_subgroup_test bls_subgroup_vectors)
            add_test(NAME bls-subgroup-test COMMAND bls_subgroup_test)
            add_custom_target(bls-subgroup-test DEPENDS bls_subgroup_test bls_subgroup_vectors)

            # ---- WGSL Fp-tower test (byte-equal to CPU oracle on Apple) ----
            set(BLS_WGSL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/gpu/wgsl")
            set(BLS_WGSL_HEADER "${CMAKE_CURRENT_BINARY_DIR}/bls_wgsl_sources.h")
            file(WRITE  ${BLS_WGSL_HEADER} "// Auto-generated. Do not edit.\n#pragma once\n\n")
            foreach(_SRC bls_fp_ops.wgsl bls_fp2.wgsl bls_fp6.wgsl bls_fp12.wgsl bls_fp_tower_kernels.wgsl)
                get_filename_component(_NAME ${_SRC} NAME_WE)
                # _NAME like "bls_fp_ops" -> we trim "bls_" prefix and uppercase parts.
                string(REGEX REPLACE "^bls_fp_ops$"           "FpOps"   _SHORT "${_NAME}")
                string(REGEX REPLACE "^bls_fp2$"              "Fp2"     _SHORT "${_SHORT}")
                string(REGEX REPLACE "^bls_fp6$"              "Fp6"     _SHORT "${_SHORT}")
                string(REGEX REPLACE "^bls_fp12$"             "Fp12"    _SHORT "${_SHORT}")
                string(REGEX REPLACE "^bls_fp_tower_kernels$" "Kernels" _SHORT "${_SHORT}")
                file(READ ${BLS_WGSL_DIR}/${_SRC} _CONTENT)
                file(APPEND ${BLS_WGSL_HEADER}
                    "// ---- ${_SRC} ----\n"
                    "static constexpr char kBLS_WGSL_${_SHORT}[] = R\"BLSWGSL(\n${_CONTENT}\n)BLSWGSL\";\n\n")
            endforeach()

            # Locate wgpu-native (Homebrew) or Dawn.
            set(_BLS_WGPU_FOUND FALSE)
            find_path(_BLS_WGPU_FLAT_INCLUDE webgpu.h
                HINTS /opt/homebrew/include /usr/local/include /usr/include)
            find_library(_BLS_WGPU_LIB NAMES wgpu_native wgpu
                HINTS /opt/homebrew/lib /usr/local/lib /usr/lib)
            if(_BLS_WGPU_FLAT_INCLUDE AND _BLS_WGPU_LIB)
                set(_BLS_WGPU_FOUND TRUE)
            endif()

            add_library(bls_wgpu_driver STATIC gpu/wgsl/bls_driver_wgpu.cpp)
            target_include_directories(bls_wgpu_driver
                PRIVATE "${CMAKE_CURRENT_BINARY_DIR}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/gpu/wgsl")
            target_compile_options(bls_wgpu_driver PRIVATE -O3)
            target_compile_features(bls_wgpu_driver PRIVATE cxx_std_17)
            if(_BLS_WGPU_FOUND)
                target_include_directories(bls_wgpu_driver PRIVATE ${_BLS_WGPU_FLAT_INCLUDE})
                target_link_libraries(bls_wgpu_driver PUBLIC ${_BLS_WGPU_LIB})
                target_compile_definitions(bls_wgpu_driver PRIVATE
                    KINET_BLS_HAS_WEBGPU=1
                    KINET_BLS_HAS_WGPU_NATIVE=1)
                message(STATUS "[bls-stage4] wgpu-native: ${_BLS_WGPU_LIB}")
            else()
                message(STATUS "[bls-stage4] wgpu-native: NOT FOUND (driver compiles to stub)")
            endif()

            add_executable(bls_fp_tower_wgsl_test test/bls_fp_tower_wgsl_test.cpp)
            target_include_directories(bls_fp_tower_wgsl_test
                PRIVATE "${CMAKE_CURRENT_BINARY_DIR}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/gpu/wgsl")
            target_compile_options(bls_fp_tower_wgsl_test PRIVATE -O3)
            target_compile_features(bls_fp_tower_wgsl_test PRIVATE cxx_std_17)
            target_link_libraries(bls_fp_tower_wgsl_test PRIVATE bls_wgpu_driver)
            add_dependencies(bls_fp_tower_wgsl_test bls_fp_tower_vectors)
            add_test(NAME bls-fp-tower-wgsl-test COMMAND bls_fp_tower_wgsl_test)
            add_custom_target(bls-fp-tower-wgsl-test
                DEPENDS bls_fp_tower_wgsl_test bls_fp_tower_vectors)

            # ---- CUDA stub driver (build-only on Apple; gated for Linux+CUDA CI) ----
            # nvcc not available on Apple; we compile only the host driver in stub
            # mode and link it to a smoke test that confirms the stub paths return
            # -1. The Linux+CUDA CI runner sets KINET_BLS_HAVE_CUDA and recompiles
            # the .cu files via nvcc.
            add_library(bls_cuda_stub STATIC gpu/cuda/bls_driver_cuda.cpp)
            target_include_directories(bls_cuda_stub
                PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/gpu/cuda")
            target_compile_options(bls_cuda_stub PRIVATE -O3)
            target_compile_features(bls_cuda_stub PRIVATE cxx_std_17)

            message(STATUS "[bls-stage4] enabled")
            message(STATUS "[bls-stage4]   subgroup vectors:        ${BLS_SUBG_VEC}")
            message(STATUS "[bls-stage4]   wgsl sources concatenated: ${BLS_WGSL_HEADER}")
            message(STATUS "[bls-stage4]   cuda driver: build-only on Apple (CI: nvcc-compiled)")
        endif()
    else()
        message(STATUS "[bls-stage1] skipped — blst not found at ${BLST_DIR}")
    endif()
endif()

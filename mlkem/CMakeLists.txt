# mlkem - ML-KEM / FIPS 203 (lattice-based key encapsulation)
#
# CPU body: vendored PQClean reference (cpp/pqclean/ml-kem-{512,768,1024}/
# clean, CC0 / public domain). Each parameter set is a standalone OBJECT
# library so its compile-time include directory points only at its own
# headers (params.h, api.h, etc are not cross-shared).
include(KinetAlgorithm)

set(_mlkem_root ${CMAKE_CURRENT_SOURCE_DIR})

# fips202 only; randombytes is split out below so KAT tests can swap a
# deterministic AES-CTR DRBG.
set(_mlkem_common_srcs
    ${_mlkem_root}/cpp/pqclean/common/fips202.c)

foreach(_set 512 768 1024)
    set(_dir ${_mlkem_root}/cpp/pqclean/ml-kem-${_set})
    file(GLOB _srcs ${_dir}/*.c)
    add_library(mlkem_pqclean_${_set} OBJECT ${_srcs} ${_mlkem_common_srcs})
    target_include_directories(mlkem_pqclean_${_set} PRIVATE
        ${_dir}
        ${_mlkem_root}/cpp/pqclean/common)
    set_target_properties(mlkem_pqclean_${_set} PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        C_STANDARD 99)
endforeach()

# Production randombytes (getentropy) backend.
add_library(mlkem_pqclean_rb OBJECT
    ${_mlkem_root}/cpp/pqclean/common/randombytes.c)
target_include_directories(mlkem_pqclean_rb PRIVATE
    ${_mlkem_root}/cpp/pqclean/common)
set_target_properties(mlkem_pqclean_rb PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    C_STANDARD 99)

kinet_add_algorithm(
    NAME    mlkem
    SOURCES cpp/mlkem.cpp c-abi/c_mlkem.cpp
    HEADERS cpp/mlkem.hpp
    CABI    c-abi/c_mlkem.cpp
)

target_sources(mlkem_cpu PRIVATE
    $<TARGET_OBJECTS:mlkem_pqclean_512>
    $<TARGET_OBJECTS:mlkem_pqclean_768>
    $<TARGET_OBJECTS:mlkem_pqclean_1024>)
target_sources(mlkem PRIVATE
    $<TARGET_OBJECTS:mlkem_pqclean_rb>)

target_include_directories(mlkem_cpu PRIVATE
    ${_mlkem_root}/cpp
    ${_mlkem_root}/cpp/pqclean/common)

# Batched ML-KEM decap Metal driver (one thread per ciphertext).
if(APPLE AND KINET_CRYPTO_ENABLE_METAL AND
   EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/gpu/metal/mlkem_batch_driver.mm)
    add_library(mlkem_batch_metal STATIC
        gpu/metal/mlkem_batch_driver.mm)
    target_compile_features(mlkem_batch_metal PUBLIC cxx_std_20)
    set_target_properties(mlkem_batch_metal PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        COMPILE_FLAGS "-fobjc-arc"
    )
    target_link_libraries(mlkem_batch_metal PUBLIC
        "-framework Metal"
        "-framework Foundation"
    )
endif()

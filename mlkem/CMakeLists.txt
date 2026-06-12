# mlkem - ML-KEM / FIPS 203 (lattice-based key encapsulation)
#
# CPU body: PQClean reference (CC0 / public domain) pulled via FetchContent
# from kinet-labs/pqclean (see deps/pqclean/). Three parameter sets.
#
# Source paths (in the fetched kinet-labs/pqclean tree):
#   ${KINETCPP_PQCLEAN_SOURCE_DIR}/common/{fips202,randombytes}.c
#   ${KINETCPP_PQCLEAN_SOURCE_DIR}/crypto_kem/ml-kem-{512,768,1024}/clean/*.c
include(KinetAlgorithm)

set(_mlkem_root ${CMAKE_CURRENT_SOURCE_DIR})
set(_pqclean ${KINETCPP_PQCLEAN_SOURCE_DIR})

# fips202 only; randombytes is split out below so KAT tests can swap a
# deterministic AES-CTR DRBG.
set(_mlkem_common_srcs
    ${_pqclean}/common/fips202.c)

foreach(_set 512 768 1024)
    set(_dir ${_pqclean}/crypto_kem/ml-kem-${_set}/clean)
    file(GLOB _srcs ${_dir}/*.c)
    add_library(mlkem_pqclean_${_set} OBJECT ${_srcs} ${_mlkem_common_srcs})
    target_include_directories(mlkem_pqclean_${_set} PRIVATE
        ${_dir}
        ${_pqclean}/common)
    set_target_properties(mlkem_pqclean_${_set} PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        C_STANDARD 99)
endforeach()

# Production randombytes (getentropy) backend.
add_library(mlkem_pqclean_rb OBJECT
    ${_pqclean}/common/randombytes.c)
target_include_directories(mlkem_pqclean_rb PRIVATE
    ${_pqclean}/common)
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
    ${_pqclean}/crypto_kem
    ${_pqclean}/common)

# Batched ML-KEM decap Metal driver (one thread per ciphertext).
if(APPLE AND CRYPTO_ENABLE_METAL AND
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

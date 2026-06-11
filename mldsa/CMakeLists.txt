# mldsa - ML-DSA / FIPS 204 (lattice-based digital signatures)
#
# CPU body: PQClean reference (CC0 / public domain) pulled via FetchContent
# from kinet-labs/pqclean (see deps/pqclean/). Three parameter sets.
#
# Source paths (in the fetched kinet-labs/pqclean tree):
#   ${KINETCPP_PQCLEAN_SOURCE_DIR}/common/{fips202,randombytes}.c
#   ${KINETCPP_PQCLEAN_SOURCE_DIR}/crypto_sign/ml-dsa-{44,65,87}/clean/*.c
include(KinetAlgorithm)

set(_mldsa_root ${CMAKE_CURRENT_SOURCE_DIR})
set(_pqclean ${KINETCPP_PQCLEAN_SOURCE_DIR})

# Common dependency: fips202 (SHAKE for the FIPS 204 hash chain). Each
# per-set OBJECT lib carries its own copy and is fully self-contained except
# for the randombytes hook -- which the linker resolves separately so that KAT
# tests can swap a deterministic AES-CTR DRBG (pqclean_kat/nistkatrng.c) in
# place of the production getentropy backend.
set(_mldsa_common_srcs
    ${_pqclean}/common/fips202.c)

# Per-parameter-set OBJECT libraries (no randombytes -- linked separately).
foreach(_set 44 65 87)
    set(_dir ${_pqclean}/crypto_sign/ml-dsa-${_set}/clean)
    file(GLOB _srcs ${_dir}/*.c)
    add_library(mldsa_pqclean_${_set} OBJECT ${_srcs} ${_mldsa_common_srcs})
    target_include_directories(mldsa_pqclean_${_set} PRIVATE
        ${_dir}
        ${_pqclean}/common)
    set_target_properties(mldsa_pqclean_${_set} PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        C_STANDARD 99)
endforeach()

# Production randombytes (getentropy backend). Built as an OBJECT library
# kept SEPARATE from mldsa_cpu so that the KAT test executable can swap a
# deterministic AES-CTR DRBG (pqclean_kat/) in place of getentropy.
# Production callers link both mldsa_cpu AND mldsa_pqclean_rb (wired through
# the umbrella `mldsa` static lib via target_sources below).
add_library(mldsa_pqclean_rb OBJECT
    ${_pqclean}/common/randombytes.c)
target_include_directories(mldsa_pqclean_rb PRIVATE
    ${_pqclean}/common)
set_target_properties(mldsa_pqclean_rb PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    C_STANDARD 99)

kinet_add_algorithm(
    NAME    mldsa
    SOURCES cpp/mldsa.cpp c-abi/c_mldsa.cpp
    HEADERS cpp/mldsa.hpp
    CABI    c-abi/c_mldsa.cpp
)

# Pull the three per-set PQClean OBJECT libs into mldsa_cpu (the body that
# tests link against). The production randombytes backend is bundled into the
# umbrella `mldsa` static lib only -- KAT tests link mldsa_cpu without it
# and pull a deterministic AES-CTR DRBG from pqclean_kat instead.
target_sources(mldsa_cpu PRIVATE
    $<TARGET_OBJECTS:mldsa_pqclean_44>
    $<TARGET_OBJECTS:mldsa_pqclean_65>
    $<TARGET_OBJECTS:mldsa_pqclean_87>)
target_sources(mldsa PRIVATE
    $<TARGET_OBJECTS:mldsa_pqclean_rb>)

target_include_directories(mldsa_cpu PRIVATE
    ${_mldsa_root}/cpp
    ${_pqclean}/crypto_sign
    ${_pqclean}/common)

# Batched ML-DSA verify Metal driver (one thread per signature). The Metal
# verify orchestrator itself emits CRYPTO_ERR_NOTIMPL until a full FIPS-204
# verify port is byte-equal to the CPU body. The CPU body (this archive) is
# now real PQClean and ships byte-equal NIST-compliant verify.
if(APPLE AND KINET_CRYPTO_ENABLE_METAL AND
   EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/gpu/metal/mldsa_batch_driver.mm)
    add_library(mldsa_batch_metal STATIC
        gpu/metal/mldsa_batch_driver.mm)
    target_compile_features(mldsa_batch_metal PUBLIC cxx_std_20)
    set_target_properties(mldsa_batch_metal PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        COMPILE_FLAGS "-fobjc-arc"
    )
    target_link_libraries(mldsa_batch_metal PUBLIC
        "-framework Metal"
        "-framework Foundation"
    )
endif()

# slhdsa - SLH-DSA / FIPS 205 (stateless hash-based signatures)
#
# CPU body: vendored PQClean reference (cpp/pqclean/sphincs-{sha2,shake}-{128,
# 192,256}f-simple/clean, CC0 / public domain). Six 'f' (fast) parameter sets;
# the 's' (small) variants are out of scope.
include(KinetAlgorithm)

set(_slhdsa_root ${CMAKE_CURRENT_SOURCE_DIR})

# common: fips202 (used by SHAKE family), sha2 (used by SHA2 family).
# randombytes is split below so KAT tests can swap a deterministic DRBG.
set(_slhdsa_common_srcs
    ${_slhdsa_root}/cpp/pqclean/common/fips202.c
    ${_slhdsa_root}/cpp/pqclean/common/sha2.c)

set(_slhdsa_sets
    sphincs-sha2-128f-simple
    sphincs-sha2-192f-simple
    sphincs-sha2-256f-simple
    sphincs-shake-128f-simple
    sphincs-shake-192f-simple
    sphincs-shake-256f-simple)

foreach(_s IN LISTS _slhdsa_sets)
    set(_dir ${_slhdsa_root}/cpp/pqclean/${_s})
    string(REPLACE "-" "_" _tag ${_s})
    file(GLOB _srcs ${_dir}/*.c)
    add_library(slhdsa_pqclean_${_tag} OBJECT ${_srcs} ${_slhdsa_common_srcs})
    target_include_directories(slhdsa_pqclean_${_tag} PRIVATE
        ${_dir}
        ${_slhdsa_root}/cpp/pqclean/common)
    set_target_properties(slhdsa_pqclean_${_tag} PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        C_STANDARD 99)
endforeach()

# Production randombytes (getentropy) backend.
add_library(slhdsa_pqclean_rb OBJECT
    ${_slhdsa_root}/cpp/pqclean/common/randombytes.c)
target_include_directories(slhdsa_pqclean_rb PRIVATE
    ${_slhdsa_root}/cpp/pqclean/common)
set_target_properties(slhdsa_pqclean_rb PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    C_STANDARD 99)

kinet_add_algorithm(
    NAME slhdsa
    SOURCES cpp/slhdsa.cpp c-abi/c_slhdsa.cpp
    HEADERS cpp/slhdsa.hpp
    CABI    c-abi/c_slhdsa.cpp
    METAL_DRIVER gpu/metal/slhdsa_driver.mm
    METAL_HEADERS gpu/metal/slhdsa_driver.h
)

# Embed all six per-set PQClean OBJECT libs into slhdsa_cpu. randombytes is
# split out -- production callers pick it up via the umbrella `slhdsa` static
# lib, while KAT tests pull a deterministic AES-CTR DRBG from pqclean_kat.
foreach(_s IN LISTS _slhdsa_sets)
    string(REPLACE "-" "_" _tag ${_s})
    target_sources(slhdsa_cpu PRIVATE $<TARGET_OBJECTS:slhdsa_pqclean_${_tag}>)
endforeach()
target_sources(slhdsa PRIVATE $<TARGET_OBJECTS:slhdsa_pqclean_rb>)

target_include_directories(slhdsa_cpu PRIVATE
    ${_slhdsa_root}/cpp
    ${_slhdsa_root}/cpp/pqclean/common)

# blst — BLS12-381 reference implementation by Supranational.
#
# This file lives at kinet-labs/crypto/bls/test/cmake/ to make it explicit:
# blst is a TEST-ONLY oracle for BLS pairing byte-equality checks.
# It is NEVER linked into the production kinet-labs/crypto/bls library.
#
# Production production-flow:
#   - kinet-labs/crypto/bls compiles to libbls.a / libbls_metal.dylib / etc.
#   - No blst dependency, no blst symbols in the shipped binary.
#
# Test-flow:
#   - bls_*_oracle.cpp generates byte-truth vectors via blst.
#   - bls_*_test.mm asserts our Metal/CUDA/CPU implementations equal blst byte-for-byte.
#
# To enable test-oracle compilation:
#   cmake -DKINET_CRYPTO_BLS_BUILD_ORACLE=ON ..

include_guard()
include(ExternalProject)

if(MSVC)
    set(BLST_BUILD_SCRIPT build.bat)
else()
    set(BLST_CC ${CMAKE_C_COMPILER})
    if(CMAKE_OSX_SYSROOT)
        set(BLST_CC "${BLST_CC} ${CMAKE_C_SYSROOT_FLAG} ${CMAKE_OSX_SYSROOT}")
    endif()
    if(CMAKE_C_OSX_DEPLOYMENT_TARGET_FLAG AND CMAKE_OSX_DEPLOYMENT_TARGET)
        set(BLST_CC "${BLST_CC} ${CMAKE_C_OSX_DEPLOYMENT_TARGET_FLAG}${CMAKE_OSX_DEPLOYMENT_TARGET}")
    endif()
    if(CMAKE_C_FLAGS)
        set(BLST_CC "${BLST_CC} ${CMAKE_C_FLAGS}")
    endif()

    set(BLST_BUILD_SCRIPT ./build.sh CC='${BLST_CC}' AR='${CMAKE_AR}' RANLIB='${CMAKE_RANLIB}')
endif()

ExternalProject_Add(
    blst_oracle
    EXCLUDE_FROM_ALL TRUE
    PREFIX ${PROJECT_BINARY_DIR}/blst-oracle
    URL https://github.com/supranational/blst/archive/refs/tags/v0.3.15.tar.gz
    URL_HASH SHA256=9e503ff6b50e044efb075d260c81c751702b3ed6f2e45394b0833834e71c3afa
    DOWNLOAD_NO_PROGRESS TRUE
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${BLST_BUILD_SCRIPT}
    BUILD_IN_SOURCE TRUE
    BUILD_BYPRODUCTS "<SOURCE_DIR>/${CMAKE_STATIC_LIBRARY_PREFIX}blst${CMAKE_STATIC_LIBRARY_SUFFIX}"
    LOG_BUILD TRUE
    LOG_OUTPUT_ON_FAILURE TRUE
    INSTALL_COMMAND ""
)
ExternalProject_Get_Property(blst_oracle SOURCE_DIR)

set(BLST_ORACLE_INCLUDE_DIR ${SOURCE_DIR}/bindings)
file(MAKE_DIRECTORY ${BLST_ORACLE_INCLUDE_DIR})

add_library(blst::oracle STATIC IMPORTED GLOBAL)
add_dependencies(blst::oracle blst_oracle)
set_target_properties(
    blst::oracle PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${BLST_ORACLE_INCLUDE_DIR}
    IMPORTED_LOCATION ${SOURCE_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}blst${CMAKE_STATIC_LIBRARY_SUFFIX}
)

message(STATUS "[bls test oracle] blst v0.3.15 (test-only, NEVER linked into production)")

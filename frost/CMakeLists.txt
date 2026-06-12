include(KinetAlgorithm)

# FROST batched pre-signing kernel.
#
# CPU canonical body lives in cpp/presign.{hpp,cpp}; the C-ABI shim wires it
# behind frost_setup / frost_partial_sign / frost_presign_batch.
#
# Round-1 nonce generation is local crypto only (no network), independent
# across (signer × slot). One GPU kernel does M signers × N batch in parallel
# and is byte-equal to the CPU body by construction.

kinet_add_algorithm(
    NAME    frost
    SOURCES cpp/presign.cpp
    HEADERS cpp/presign.hpp
    CABI    c-abi/c_frost.cpp
)

# CPU body needs sha256 (HKDF backbone). secp256k1 field/curve headers are
# header-only and don't pull a separate link.
target_link_libraries(frost_cpu PUBLIC sha256_cpu)
target_link_libraries(frost     PUBLIC sha256_cpu)
target_include_directories(frost_cpu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../sha256/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../secp256k1/cpp)
target_include_directories(frost PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../sha256/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../secp256k1/cpp)

# =============================================================================
# CUDA backend (host polyfill). Same .cu compiles as plain C++ when CUDA is
# disabled and exposes frost_presign_cuda_host() as the byte-equal oracle.
# =============================================================================
add_library(frost_cuda STATIC gpu/cuda/frost_presign.cu)
set_source_files_properties(gpu/cuda/frost_presign.cu PROPERTIES LANGUAGE CXX)
target_compile_features(frost_cuda PUBLIC cxx_std_20)
set_target_properties(frost_cuda PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Test wiring lives in the top-level CMakeLists.txt under the
# `if(CRYPTO_BUILD_TESTS)` block — that block is the only point where
# `enable_testing()` has been called, so add_test must register from there
# (subdirectory calls land in a stale CTestTestfile).


include(KinetAlgorithm)

# CGGMP21 batched pre-signing kernel.
#
# Wired: secp256k1 portion (R_i = k_i * G) + Paillier ciphertext (K_i, G_cmt)
# + Π^enc range proof using the LP-163 Karatsuba 2048-bit modexp primitive.
# Round-1 PresignRecord is fully populated (status = 0 on success).

kinet_add_algorithm(
    NAME    cggmp21
    SOURCES cpp/presign.cpp cpp/paillier.cpp
    HEADERS cpp/presign.hpp cpp/paillier.hpp
    CABI    c-abi/c_cggmp21.cpp
)

target_link_libraries(cggmp21_cpu PUBLIC sha256_cpu modexp)
target_link_libraries(cggmp21     PUBLIC sha256_cpu modexp)
target_include_directories(cggmp21_cpu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../sha256/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../secp256k1/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../modexp/cpp)
target_include_directories(cggmp21 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../sha256/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../secp256k1/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../modexp/cpp)

# CUDA backend (host polyfill — same .cu compiles as plain C++ when CUDA is
# disabled, exposing cggmp21_presign_cuda_host as the byte-equal oracle that
# forwards to the CPU canonical body).
add_library(cggmp21_cuda STATIC gpu/cuda/cggmp21_presign.cu)
set_source_files_properties(gpu/cuda/cggmp21_presign.cu PROPERTIES LANGUAGE CXX)
target_compile_features(cggmp21_cuda PUBLIC cxx_std_20)
set_target_properties(cggmp21_cuda PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(cggmp21_cuda PUBLIC cggmp21_cpu)
target_include_directories(cggmp21_cuda PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../secp256k1/cpp)


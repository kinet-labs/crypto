# keccak - first-party Keccak-256 (Ethereum hash)
# Canonical implementation per Keccak Reference v3.0 (Bertoni-Daemen-Peeters-Van
# Assche), pre-FIPS-202 padding (delimiter 0x01) as used by Ethereum.

include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    keccak
    SOURCES cpp/keccak.cpp
    HEADERS ../include/kinet/crypto/keccak.h
    CABI    c-abi/c_keccak.cpp
)

# Make the public header reachable as <kinet/crypto/keccak.h>.
target_include_directories(keccak_cpu PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
target_include_directories(keccak PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

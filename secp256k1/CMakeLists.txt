# secp256k1 - Bitcoin / Ethereum curve (first-party ecrecover)
# CPU body lives in cpp/ecrecover.cpp + cpp/{curve,field}.hpp; no third-party
# crypto library is linked.

include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    secp256k1
    SOURCES cpp/ecrecover.cpp
    HEADERS ../include/kinet/crypto/secp256k1.h cpp/curve.hpp cpp/field.hpp
    CABI    c-abi/c_secp256k1.cpp
    METAL_DRIVER gpu/metal/secp256k1_first_party_driver.mm
    METAL_HEADERS gpu/metal/secp256k1_driver.h
)

target_include_directories(secp256k1_cpu PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
target_include_directories(secp256k1 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

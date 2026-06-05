# bls - BLS12-381 (consensus signatures + EIP-2537 precompiles)
include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    bls
    SOURCES c-abi/c_bls.cpp
    HEADERS cpp/bls.hpp
    CABI    c-abi/c_bls.cpp
    METAL_DRIVER gpu/metal/bls_driver.mm
    METAL_HEADERS gpu/metal/bls_driver.h
)

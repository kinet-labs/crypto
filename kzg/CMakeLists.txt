# kzg - KZG polynomial commitments (EIP-4844)
include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    kzg
    SOURCES c-abi/c_kzg.cpp
    HEADERS cpp/kzg.hpp
    CABI    c-abi/c_kzg.cpp
)

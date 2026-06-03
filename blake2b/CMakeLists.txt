# blake2b - BLAKE2b RFC 7693
include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    blake2b
    SOURCES cpp/blake2b.cpp c-abi/blake2b_full.cpp
    HEADERS cpp/blake2b.hpp
    CABI    c-abi/c_blake2b.cpp
)

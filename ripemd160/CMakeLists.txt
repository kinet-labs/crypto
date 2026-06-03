# ripemd160 - RIPEMD-160 (Ethereum precompile 0x03)
include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    ripemd160
    SOURCES cpp/ripemd160.cpp
    HEADERS cpp/ripemd160.hpp
    CABI    c-abi/c_ripemd160.cpp
)

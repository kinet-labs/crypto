# modexp - EVM big-int modular exponentiation (EIP-198) + mulmod
include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    modexp
    SOURCES c-abi/c_modexp.cpp
    HEADERS cpp/modexp.hpp cpp/mulmod.hpp
    CABI    c-abi/c_modexp.cpp
)

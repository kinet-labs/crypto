# modexp - EVM big-int modular exponentiation (EIP-198) + evm256_{add,mul}mod
include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    modexp
    SOURCES
        c-abi/c_modexp.cpp
        cpp/modexp.cpp
        cpp/mulmod.cpp
    HEADERS cpp/modexp.hpp cpp/mulmod.hpp
    CABI    c-abi/c_modexp.cpp
)

# CPU body needs intx + evmmax (Montgomery REDC + ModArith for evmmax::modinv).
target_link_libraries(modexp_cpu PUBLIC intx::intx evmmax::evmmax)
target_link_libraries(modexp     PUBLIC intx::intx evmmax::evmmax)

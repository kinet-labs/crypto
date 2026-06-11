# bn254 - alt_bn128 (EIP-196 / EIP-197 / EIP-1108)
include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    bn254
    SOURCES
        c-abi/c_bn254.cpp
        cpp/bn254.cpp
        cpp/pairing/pairing.cpp
    HEADERS
        cpp/bn254.hpp
        cpp/ecc.hpp
        cpp/pairing/fields.hpp
        cpp/pairing/utils.hpp
        cpp/pairing/field_template.hpp
    CABI    c-abi/c_bn254.cpp
    METAL_DRIVER  gpu/metal/zk_metal.mm
    METAL_HEADERS gpu/metal/zk_metal.h
)

# CPU body needs intx + evmmax for ModArith / EC field arithmetic.
target_link_libraries(bn254_cpu PUBLIC intx::intx evmmax::evmmax)
target_link_libraries(bn254     PUBLIC intx::intx evmmax::evmmax)

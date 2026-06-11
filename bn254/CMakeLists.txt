# bn254 - alt_bn128 (EIP-196 / EIP-197 / EIP-1108)
include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    bn254
    SOURCES
        c-abi/c_bn254.cpp
        cpp/bn254.cpp
        cpp/bn254_hash_to_curve.cpp
        cpp/bn254_pairing.cpp
    HEADERS
        cpp/bn254.hpp
        cpp/bn254_fp.hpp
        cpp/bn254_fp2.hpp
        cpp/bn254_fp6.hpp
        cpp/bn254_fp12.hpp
        cpp/bn254_g1.hpp
        cpp/bn254_g2.hpp
        cpp/bn254_hash_to_curve.hpp
        cpp/bn254_pairing.hpp
        cpp/ecc.hpp
    CABI    c-abi/c_bn254.cpp
    METAL_DRIVER  gpu/metal/zk_metal.mm
    METAL_HEADERS gpu/metal/zk_metal.h
)

# CPU body needs intx + evmmax for ModArith / EC field arithmetic.
target_link_libraries(bn254_cpu PUBLIC intx::intx evmmax::evmmax)
target_link_libraries(bn254     PUBLIC intx::intx evmmax::evmmax)

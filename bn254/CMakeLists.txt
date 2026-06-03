# bn254 - alt_bn128 (EIP-196/197/1108)
include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    bn254
    SOURCES c-abi/c_bn254.cpp
    HEADERS cpp/bn254.hpp cpp/pairing/fields.hpp cpp/pairing/utils.hpp cpp/pairing/field_template.hpp
    CABI    c-abi/c_bn254.cpp
    METAL_DRIVER gpu/metal/zk_metal.mm
    METAL_HEADERS gpu/metal/zk_metal.h
)

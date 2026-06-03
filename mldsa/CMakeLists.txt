include(KinetAlgorithm)
kinet_add_algorithm(
    NAME mldsa
    SOURCES c-abi/c_mldsa.cpp
    CABI    c-abi/c_mldsa.cpp
    METAL_DRIVER gpu/metal/mldsa_driver.mm
    METAL_HEADERS gpu/metal/mldsa_driver.h
)

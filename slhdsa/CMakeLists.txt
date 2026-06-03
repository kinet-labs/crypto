include(KinetAlgorithm)
kinet_add_algorithm(
    NAME slhdsa
    SOURCES c-abi/c_slhdsa.cpp
    CABI    c-abi/c_slhdsa.cpp
    METAL_DRIVER gpu/metal/slhdsa_driver.mm
    METAL_HEADERS gpu/metal/slhdsa_driver.h
)

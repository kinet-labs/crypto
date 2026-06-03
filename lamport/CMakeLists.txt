include(KinetAlgorithm)
kinet_add_algorithm(
    NAME lamport
    SOURCES c-abi/c_lamport.cpp
    CABI    c-abi/c_lamport.cpp
    METAL_DRIVER gpu/metal/lamport_driver.mm
    METAL_HEADERS gpu/metal/lamport_driver.h
)

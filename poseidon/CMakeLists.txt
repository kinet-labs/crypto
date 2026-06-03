include(KinetAlgorithm)
kinet_add_algorithm(
    NAME poseidon
    SOURCES c-abi/c_poseidon.cpp
    CABI    c-abi/c_poseidon.cpp
    METAL_DRIVER gpu/metal/poseidon2_driver.mm
    METAL_HEADERS gpu/metal/poseidon2_driver.h
)

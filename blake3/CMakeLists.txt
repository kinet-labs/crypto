# blake3 - BLAKE3 hash (Bao tree)
include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    blake3
    SOURCES c-abi/c_blake3.cpp
    CABI    c-abi/c_blake3.cpp
    METAL_DRIVER gpu/metal/blake3_driver.mm
    METAL_HEADERS gpu/metal/blake3_driver.h
)

include(KinetAlgorithm)
kinet_add_algorithm(
    NAME mlkem
    SOURCES c-abi/c_mlkem.cpp
    CABI    c-abi/c_mlkem.cpp
    METAL_DRIVER gpu/metal/mlkem_driver.mm
    METAL_HEADERS gpu/metal/mlkem_driver.h
)

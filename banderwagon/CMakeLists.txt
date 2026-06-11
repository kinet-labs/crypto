# banderwagon - Bandersnatch base field Fp (BLS12-381 scalar field), scalar
# field Fr, and the Banderwagon group element (prime-order quotient of
# Bandersnatch by its 2-torsion).
include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    banderwagon
    SOURCES cpp/fp.cpp cpp/fr.cpp cpp/element.cpp cpp/multiexp.cpp
    HEADERS cpp/fp.hpp cpp/fr.hpp cpp/element.hpp cpp/multiexp.hpp
    CABI    c-abi/c_banderwagon.cpp
    METAL_DRIVER  gpu/metal/banderwagon_driver.mm
    METAL_HEADERS gpu/metal/banderwagon_driver.h
)

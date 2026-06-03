include(KinetAlgorithm)
kinet_add_algorithm(
    NAME ipa
    SOURCES c-abi/c_ipa.cpp
    CABI    c-abi/c_ipa.cpp
    METAL_DRIVER gpu/metal/ipa_driver.mm
    METAL_HEADERS gpu/metal/ipa_driver.h
)

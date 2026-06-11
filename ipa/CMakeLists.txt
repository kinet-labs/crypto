include(KinetAlgorithm)
kinet_add_algorithm(
    NAME    ipa
    SOURCES cpp/ipa.cpp
    HEADERS cpp/ipa.hpp
    CABI    c-abi/c_ipa.cpp
    METAL_DRIVER  gpu/metal/ipa_driver.mm
    METAL_HEADERS gpu/metal/ipa_driver.h
)

# IPA depends on the first-party Banderwagon arithmetic (Element / Fr / MSM).
target_link_libraries(ipa_cpu PUBLIC banderwagon_cpu)
target_link_libraries(ipa     PUBLIC banderwagon_cpu)

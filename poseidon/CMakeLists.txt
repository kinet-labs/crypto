# poseidon - Poseidon2 over BN254 scalar field (default t=2, rF=6, rP=50, d=5).
# First-party CPU body matches gnark-crypto v0.20.1; KAT vectors generated
# from gnark-crypto directly.
include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    poseidon
    SOURCES cpp/poseidon.cpp
    HEADERS cpp/poseidon.hpp cpp/fr_bn254.hpp cpp/poseidon_constants.hpp
    CABI    c-abi/c_poseidon.cpp
)

# Batched Poseidon2-t2 Metal driver (one thread per state, byte-equal to the
# CPU body). Companion file: gpu/metal/poseidon2_t2_batch.metal.
if(APPLE AND KINET_CRYPTO_ENABLE_METAL)
    add_library(poseidon2_t2_batch_metal STATIC
        gpu/metal/poseidon2_t2_batch_driver.mm)
    target_compile_features(poseidon2_t2_batch_metal PUBLIC cxx_std_20)
    set_target_properties(poseidon2_t2_batch_metal PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        COMPILE_FLAGS "-fobjc-arc"
    )
    target_link_libraries(poseidon2_t2_batch_metal PUBLIC
        "-framework Metal"
        "-framework Foundation"
    )
endif()

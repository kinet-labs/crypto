# secp256k1 - Bitcoin / Ethereum curve (first-party ecrecover)
# CPU body lives in cpp/ecrecover.cpp + cpp/{curve,field}.hpp; no third-party
# crypto library is linked.

include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    secp256k1
    SOURCES cpp/ecrecover.cpp cpp/batch_inv.cpp
    HEADERS ../include/kinet/crypto/secp256k1.h
            cpp/curve.hpp cpp/field.hpp
            cpp/batch_inv.hpp cpp/windowed_g_table.hpp
            cpp/ecrecover_pipeline.hpp
    CABI    c-abi/c_secp256k1.cpp
    METAL_DRIVER gpu/metal/secp256k1_first_party_driver.mm
    METAL_HEADERS gpu/metal/secp256k1_driver.h
)

target_include_directories(secp256k1_cpu PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
target_include_directories(secp256k1 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

# v0.63 Stage A — Montgomery batch inversion Metal driver. Separate library
# because kinet_add_algorithm only takes a single METAL_DRIVER slot.
if(APPLE AND KINET_CRYPTO_ENABLE_METAL)
    add_library(secp256k1_batch_inv_metal STATIC
        gpu/metal/secp256k1_batch_inv_driver.mm)
    target_include_directories(secp256k1_batch_inv_metal PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    )
    target_compile_features(secp256k1_batch_inv_metal PUBLIC cxx_std_20)
    set_target_properties(secp256k1_batch_inv_metal PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        COMPILE_FLAGS "-fobjc-arc"
    )
    target_link_libraries(secp256k1_batch_inv_metal PUBLIC
        "-framework Metal"
        "-framework Foundation"
    )
endif()

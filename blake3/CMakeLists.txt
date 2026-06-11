# blake3 - BLAKE3 hash (Bao tree). First-party CPU + Metal + KAT against the
# official test_vectors.json from github.com/BLAKE3-team/BLAKE3.
include(KinetAlgorithm)

set(_blake3_root ${CMAKE_CURRENT_SOURCE_DIR})

# Reference C as an OBJECT lib so it links once into blake3_cpu without
# leaking into the public include path. C99 + portable-only dispatch.
add_library(blake3_reference OBJECT
    ${_blake3_root}/cpp/blake3-reference/blake3.c
    ${_blake3_root}/cpp/blake3-reference/blake3_dispatch.c
    ${_blake3_root}/cpp/blake3-reference/blake3_portable.c)
target_include_directories(blake3_reference PUBLIC
    ${_blake3_root}/cpp/blake3-reference)
target_compile_definitions(blake3_reference PRIVATE
    BLAKE3_NO_SSE2
    BLAKE3_NO_SSE41
    BLAKE3_NO_AVX2
    BLAKE3_NO_AVX512
    BLAKE3_USE_NEON=0)
set_target_properties(blake3_reference PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    C_STANDARD 99
    C_VISIBILITY_PRESET hidden)

kinet_add_algorithm(
    NAME    blake3
    SOURCES cpp/blake3.cpp
    HEADERS cpp/blake3.hpp
    CABI    c-abi/c_blake3.cpp
)

# Batched BLAKE3 Metal driver (one thread per input, byte-equal to the CPU
# body). Compiled separately from the legacy blake3_driver.mm/blake3.metal,
# which remain for backwards compatibility but are not on the canonical path.
if(APPLE AND KINET_CRYPTO_ENABLE_METAL)
    add_library(blake3_batch_metal STATIC
        gpu/metal/blake3_batch_driver.mm)
    target_compile_features(blake3_batch_metal PUBLIC cxx_std_20)
    set_target_properties(blake3_batch_metal PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        COMPILE_FLAGS "-fobjc-arc"
    )
    target_link_libraries(blake3_batch_metal PUBLIC
        "-framework Metal"
        "-framework Foundation"
    )
endif()

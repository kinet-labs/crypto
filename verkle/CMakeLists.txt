include(KinetAlgorithm)
kinet_add_algorithm(
    NAME verkle
    SOURCES cpp/verkle.cpp
    HEADERS cpp/verkle.hpp
    CABI    c-abi/c_verkle.cpp
)

if(KINET_CRYPTO_BUILD_TESTS)
    add_executable(verkle_test test/verkle_test.cpp)
    target_link_libraries(verkle_test PRIVATE verkle_cpu)
    target_include_directories(verkle_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/cpp
    )
    add_test(NAME verkle_test COMMAND verkle_test)
endif()

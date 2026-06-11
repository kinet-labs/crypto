include(KinetAlgorithm)
kinet_add_algorithm(NAME poly_mul SOURCES cpp/poly_mul.cpp CABI c-abi/c_poly_mul.cpp)

# poly_mul host body uses ntt's namespace (Context, forward/inverse, pow_mod);
# put ntt/cpp on the include path and link the ntt static lib.
target_include_directories(poly_mul_cpu PUBLIC
    ${CMAKE_SOURCE_DIR}/ntt/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/cpp
)
target_include_directories(poly_mul PUBLIC
    ${CMAKE_SOURCE_DIR}/ntt/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/cpp
)
target_link_libraries(poly_mul_cpu PUBLIC ntt_cpu)
target_link_libraries(poly_mul     PUBLIC ntt_cpu ntt)

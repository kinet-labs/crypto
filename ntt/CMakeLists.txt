include(KinetAlgorithm)
kinet_add_algorithm(NAME ntt SOURCES cpp/ntt.cpp CABI c-abi/c_ntt.cpp)

# Body in cpp/ntt.cpp; C-ABI shim in c-abi/c_ntt.cpp.
target_include_directories(ntt_cpu PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/cpp)
target_include_directories(ntt     PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/cpp)

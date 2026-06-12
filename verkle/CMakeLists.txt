include(KinetAlgorithm)
kinet_add_algorithm(
    NAME verkle
    SOURCES cpp/verkle.cpp
    HEADERS cpp/verkle.hpp
    CABI    c-abi/c_verkle.cpp
)

# Tests are registered in the top-level CMakeLists.txt after enable_testing()
# has been called -- per-algo add_test() before that point silently fails to
# register with CTest. See top-level "Per-algorithm tests" block.

# sha256 - SHA-256 (FIPS 180-4)
include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    sha256
    SOURCES cpp/sha256.cpp
    HEADERS cpp/sha256.hpp
    CABI    c-abi/c_sha256.cpp
)

# ringtail — Ring-LWE threshold signature.
#
# CPU body in cpp/ringtail.{hpp,cpp}; C-ABI shim in c-abi/c_ringtail.cpp.
# Reuses poly_mul/cpp negacyclic mul (which itself reuses ntt/cpp) for the
# polynomial-mul hot path. SHA-256 backs the deterministic stream PRNG used
# by setup/sign and the Fiat-Shamir challenge transcript.

include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    ringtail
    SOURCES cpp/ringtail.cpp
    HEADERS cpp/ringtail.hpp
    CABI    c-abi/c_ringtail.cpp
)

# Body depends on poly_mul (negacyclic Z_q[X]/(X^N+1) mul) and sha256
# (transcript hash + KDF). poly_mul transitively pulls in ntt.
target_link_libraries(ringtail_cpu PUBLIC poly_mul_cpu sha256_cpu)
target_include_directories(ringtail_cpu PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/poly_mul/cpp>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/sha256/cpp>
)
target_include_directories(ringtail PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/poly_mul/cpp>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/sha256/cpp>
)
target_link_libraries(ringtail PUBLIC poly_mul_cpu sha256_cpu)

# attestation - confidential-compute attestation primitives
#
# Software-only parsers for AMD SEV-SNP, Intel TDX, NVIDIA NRAS evidence,
# and the composite NodeConfidentialAttestation used as the root binding
# every confidential-compute fact about a node.

include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    attestation
    SOURCES
        cpp/sev_snp.cpp
        cpp/tdx.cpp
        cpp/nv_attestation.cpp
        cpp/rim.cpp
        cpp/composite.cpp
    HEADERS
        ../include/kinet/crypto/attestation/attestation.h
        ../include/kinet/crypto/attestation/composite.h
    CABI    c-abi/c_attestation.cpp
)

# The attestation parsers depend on keccak256 from the keccak module.
target_link_libraries(attestation_cpu PUBLIC keccak_cpu)
target_link_libraries(attestation     PUBLIC keccak_cpu)

# Make the public header reachable as <kinet/crypto/attestation/...>.
target_include_directories(attestation_cpu PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/attestation/include>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/attestation/c-abi>
)
target_include_directories(attestation PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/attestation/include>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/attestation/c-abi>
)

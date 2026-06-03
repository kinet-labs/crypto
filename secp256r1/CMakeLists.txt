# secp256r1 - NIST P-256 curve (RIP-7212 precompile)
# Same intx/evmc dependency situation as secp256k1; Phase 3 ports the CPU body.

include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    secp256r1
    SOURCES c-abi/c_secp256r1.cpp
    HEADERS cpp/secp256r1.hpp
    CABI    c-abi/c_secp256r1.cpp
)

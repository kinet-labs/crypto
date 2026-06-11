# evm256 — 256-bit modular arithmetic precompile (addmod, mulmod).
#
# First-party body at cpp/evm256.cpp. Built on intx + evmmax (header-only,
# vendored at crypto/deps/). No blst, no external runtime libraries.

include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    evm256
    SOURCES cpp/evm256.cpp c-abi/c_evm256.cpp
    HEADERS cpp/evm256.hpp
    CABI    c-abi/c_evm256.cpp
)

# The CPU body uses intx + evmmax (header-only).
target_link_libraries(evm256_cpu PRIVATE intx::intx evmmax::evmmax)
target_link_libraries(evm256     PRIVATE intx::intx evmmax::evmmax)

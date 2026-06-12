# secp256r1 — NIST P-256 curve (RIP-7212 / EIP-7951 precompile).
#
# CPU body (cpp/secp256r1.cpp) requires:
#   * intx                          (vendored at crypto/deps/intx)
#   * evmmax::ModArith              (vendored at crypto/deps/evmmax)
#   * cevm_support headers          (first-party, cpp/cevm_support/)
#   * sha256_cpu                    (in-tree SHA-256, used by the C-ABI shim)
#
# Wire is unconditional: every supported host yields a real verify result
# (CRYPTO_OK / CRYPTO_ERR_VERIFY). No NOTIMPL path on this algorithm.

include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    secp256r1
    SOURCES cpp/secp256r1.cpp
    HEADERS cpp/secp256r1.hpp
    CABI    c-abi/c_secp256r1.cpp
)

target_link_libraries(secp256r1_cpu PUBLIC
    intx::intx
    evmmax::evmmax
)

# C-ABI shim calls cevm::crypto::sha256 directly — link the CPU body
# (no umbrella, no OpenSSL). sha256_cpu PUBLIC-exports cpp/sha256.hpp.
target_link_libraries(secp256r1 PUBLIC sha256_cpu)

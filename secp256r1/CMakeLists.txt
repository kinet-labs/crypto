# secp256r1 — NIST P-256 curve (RIP-7212 / EIP-7951 precompile).
#
# CPU body (cpp/secp256r1.cpp) transitively requires:
#   * intx (vendored at crypto/deps/intx)
#   * evmmax::ModArith (vendored at crypto/deps/evmmax)
#   * cevm support headers ecc.hpp + hash_types.h (sourced via
#     KINET_CRYPTO_CEVM_SUPPORT_DIR; pre-existing cevm-internal headers
#     not yet rehomed into crypto/<alg>/cpp/).
#
# When the deps + support headers are present, the cpp body links into
# secp256r1_cpu. Otherwise we fall back to the NOTIMPL c-abi stub.
include(KinetAlgorithm)

if(KINET_CRYPTO_CEVM_SUPPORT_AVAILABLE)
    kinet_add_algorithm(
        NAME    secp256r1
        SOURCES cpp/secp256r1.cpp
        HEADERS cpp/secp256r1.hpp
        CABI    c-abi/c_secp256r1.cpp
    )
    target_include_directories(secp256r1_cpu PRIVATE
        ${KINET_CRYPTO_CEVM_SUPPORT_DIR}
    )
    target_link_libraries(secp256r1_cpu PRIVATE intx::intx evmmax::evmmax)
else()
    kinet_add_algorithm(
        NAME    secp256r1
        SOURCES c-abi/c_secp256r1.cpp
        HEADERS cpp/secp256r1.hpp
        CABI    c-abi/c_secp256r1.cpp
    )
endif()

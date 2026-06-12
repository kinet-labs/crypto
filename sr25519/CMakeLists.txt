# =============================================================================
# kinet-labs/crypto/sr25519
# =============================================================================
# Pure-C sr25519 (Schnorrkel) — Substrate-compatible.
#
# Pulls kinet-labs/sr25519-crust via FetchContent (no Rust toolchain) and exposes
# the brand-neutral C-ABI surface declared in c-abi/crypto.h:
#
#   int sr25519_sign  (const uint8_t sk[32], const uint8_t* msg, size_t len, uint8_t sig[64]);
#   int sr25519_verify(const uint8_t pk[32], const uint8_t* msg, size_t len, const uint8_t sig[64]);
#
# The donna keypair layout is [secret(32) | nonce(32) | public(32)] = 96 B,
# but the C-ABI takes a 32-byte SEED (Substrate convention) — donna_bridge.c
# expands to the donna keypair on each call.
#
# donna_bridge.c is isolated from the C-ABI shim because the donna sr25519.h
# declares functions named sr25519_sign / sr25519_verify with different
# signatures that would clash with the brand-neutral C-ABI declarations.
# =============================================================================

# kinet-labs/sr25519-crust exposes Substrate-style symbol names by default
# (sr25519_sign, sr25519_verify) which clash with the brand-neutral C-ABI
# in kinet-labs/crypto/c-abi/crypto.h (same names, different argument shapes).
# We pull v0.2.0+ which supports compile-time namespacing and prefix every
# donna public symbol with `kinet_donna_`. donna_bridge.c calls the renamed
# entry points; the C-ABI shim sees only its own brand-neutral names.
set(SR25519_NAMESPACE "kinet_donna_" CACHE STRING "" FORCE)

include(FetchContent)
FetchContent_Declare(sr25519_crust
    GIT_REPOSITORY https://github.com/kinet-labs/sr25519-crust.git
    GIT_TAG        v0.2.0)
FetchContent_MakeAvailable(sr25519_crust)

# Enable C for donna_bridge.c (project may be C++-only at top level).
enable_language(C)

include(KinetAlgorithm)
kinet_add_algorithm(NAME sr25519
    SOURCES c-abi/c_sr25519.cpp c-abi/donna_bridge.c
    HEADERS c-abi/donna_bridge.h
    CABI    c-abi/c_sr25519.cpp)

target_link_libraries(sr25519_cpu PUBLIC kinet-labs::sr25519-crust)
target_link_libraries(sr25519     PUBLIC kinet-labs::sr25519-crust)

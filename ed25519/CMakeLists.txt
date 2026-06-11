# ed25519 - EdDSA on Curve25519 (RFC 8032)
#
# Host CPU body wraps ed25519-donna (Andrew Moon, public domain) vendored at
# cpp/ed25519-donna/. See cpp/ed25519-donna/PROVENANCE for the pinned commit
# and the file manifest.
#
# Compile-time switches set in cpp/ed25519.cpp:
#   ED25519_CUSTOMHASH      -> SHA-512 from cpp/ed25519-donna/ed25519-hash-custom.h
#   ED25519_CUSTOMRANDOM    -> xorshift PRNG (batch_verify only) from -randombytes-custom.h
#   ED25519_NO_INLINE_ASM   -> portable C path (works on x86-64 and Apple Silicon)
#   ED25519_SUFFIX=_donna   -> namespaces upstream symbols out of the public C ABI
#
# Targets (via kinet_add_algorithm):
#   ed25519_cpu      static lib, host CPU implementation
#   ed25519          umbrella static lib, links cpu + Metal driver

include(KinetAlgorithm)

kinet_add_algorithm(
    NAME    ed25519
    SOURCES cpp/ed25519.cpp
    HEADERS cpp/ed25519.hpp
    CABI    c-abi/c_ed25519.cpp
)

# ed25519.cpp pulls in cpp/ed25519-donna/ed25519.c via #include; ed25519-donna
# in turn includes its sibling headers from the same directory. Both the
# wrapper TU and downstream consumers need the cpp/ folder on the include path.
target_include_directories(ed25519_cpu PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/cpp
)
target_include_directories(ed25519 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/cpp
)

# Quiet upstream warnings - vendored public-domain code, do not patch.
target_compile_options(ed25519_cpu PRIVATE
    -Wno-unused-function
    -Wno-unused-parameter
    -Wno-unused-but-set-variable
    -Wno-sign-compare
    -Wno-shadow
    -Wno-cast-qual
    -Wno-strict-aliasing
)

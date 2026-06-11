# ed25519 - EdDSA on Curve25519 (RFC 8032)
#
# Host CPU body wraps ed25519-donna (Andrew Moon, public domain) pulled via
# FetchContent from kinet-labs/ed25519-donna (see deps/ed25519-donna/). The
# upstream C TU (ed25519.c) is #include'd directly into cpp/ed25519.cpp so
# the kinet wrapper namespace owns the public surface.
#
# Compile-time switches set in cpp/ed25519.cpp:
#   ED25519_CUSTOMHASH      -> SHA-512 from cpp/ed25519-hash-custom.h (kinet shim)
#   ED25519_CUSTOMRANDOM    -> xorshift PRNG from cpp/ed25519-randombytes-custom.h (kinet shim)
#   ED25519_NO_INLINE_ASM   -> portable C path (works on x86-64 and Apple Silicon)
#   ED25519_SUFFIX=_donna   -> namespaces upstream symbols out of the public C ABI
#
# The kinet shim headers (cpp/ed25519-hash-custom.h, cpp/ed25519-randombytes-custom.h)
# share a name with upstream stubs in the fetched kinet-labs/ed25519-donna tree.
# Resolution: cpp/ is on the include path BEFORE ${KINETCPP_ED25519_DONNA_SOURCE_DIR},
# so the kinet shims win. The upstream files in the fetched tree are unchanged.
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

# Include path ordering matters: cpp/ first so the kinet shim headers
# (ed25519-hash-custom.h, ed25519-randombytes-custom.h) win over the upstream
# stubs of the same name in the fetched kinet-labs/ed25519-donna tree. After cpp/,
# the fetched source dir provides ed25519.c + sibling ed25519-donna-*.h files.
target_include_directories(ed25519_cpu PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/cpp
    ${KINETCPP_ED25519_DONNA_SOURCE_DIR}
)
target_include_directories(ed25519 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/cpp
    ${KINETCPP_ED25519_DONNA_SOURCE_DIR}
)

# Quiet upstream warnings - public-domain reference code, do not patch.
target_compile_options(ed25519_cpu PRIVATE
    -Wno-unused-function
    -Wno-unused-parameter
    -Wno-unused-but-set-variable
    -Wno-sign-compare
    -Wno-shadow
    -Wno-cast-qual
    -Wno-strict-aliasing
)

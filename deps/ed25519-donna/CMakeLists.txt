# ed25519-donna — Andrew Moon's portable Ed25519 reference (RFC 8032).
#
# Source:  github.com/kinet-labs/ed25519-donna (kinet-labs-maintained snapshot of
#          floodyberry/ed25519-donna pinned commit
#          8757bd4cd209cb032853ece0ce413f122eef212c)
# Pinned:  v0.1.0-kinet-labs
# License: Public Domain (no LICENSE file upstream; documented in
#          kinet-labs/ed25519-donna/LICENSE-NOTICE.md).
# Layout:  flat. ed25519.c is the single TU; sibling headers
#          (ed25519-donna-*.h, ed25519-hash-custom.h, ed25519-hash.h,
#          ed25519-randombytes-custom.h, ed25519-randombytes.h) include
#          via #include "<name>.h".
#
# Pulled via FetchContent from kinet-labs/ed25519-donna. ed25519/cpp/ed25519.cpp
# pulls in ed25519.c via #include and configures it with compile-time switches
# (ED25519_CUSTOMHASH, ED25519_CUSTOMRANDOM, ED25519_NO_INLINE_ASM,
# ED25519_SUFFIX=_donna). The wrapper TU and downstream consumers add the
# fetched source dir to their include path so the ed25519-donna sibling
# headers resolve.
#
# Like pqclean, this entry only fetches sources -- ed25519/CMakeLists.txt owns
# the compile/link wiring (it kinet_add_algorithm()s ed25519_cpu and adds the
# fetched include dir).

include(FetchContent)

FetchContent_Declare(kinet-labs_ed25519_donna
    GIT_REPOSITORY https://github.com/kinet-labs/ed25519-donna.git
    GIT_TAG        v0.1.0-kinet-labs
    GIT_SHALLOW    TRUE
)
FetchContent_GetProperties(kinet-labs_ed25519_donna)
if(NOT kinet-labs_ed25519_donna_POPULATED)
    FetchContent_Populate(kinet-labs_ed25519_donna)
endif()

set(KINETCPP_ED25519_DONNA_SOURCE_DIR ${kinet-labs_ed25519_donna_SOURCE_DIR}
    CACHE INTERNAL "Path to the kinet-labs/ed25519-donna fetched source tree")

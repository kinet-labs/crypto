# blake3-reference — BLAKE3 reference C implementation.
#
# Source:  github.com/kinet-labs/blake3-reference (kinet-labs-maintained snapshot of
#          BLAKE3-team/BLAKE3 v1.5.0)
# Pinned:  v1.5.0
# License: CC0 1.0 OR Apache-2.0 (dual-licensed; see upstream LICENSE_CC0 /
#          LICENSE_A2 / LICENSE_A2LLVM).
# Layout:  full BLAKE3 repo. C reference is at c/{blake3,blake3_dispatch,
#          blake3_portable}.c with c/blake3.h as the public header.
#
# Pulled via FetchContent from kinet-labs/blake3-reference. blake3/CMakeLists.txt
# builds an OBJECT library `blake3_reference` from the three portable C TUs and
# embeds it into blake3_cpu. SIMD paths (SSE2/SSE4.1/AVX2/AVX512/NEON) are
# disabled at compile time via BLAKE3_NO_SSE2 / BLAKE3_NO_SSE41 /
# BLAKE3_NO_AVX2 / BLAKE3_NO_AVX512 / BLAKE3_USE_NEON=0, mirroring upstream's
# BLAKE3_DISABLE_SIMD() cmake macro.

include(FetchContent)

FetchContent_Declare(kinet-labs_blake3_reference
    GIT_REPOSITORY https://github.com/kinet-labs/blake3-reference.git
    GIT_TAG        v1.5.0
    GIT_SHALLOW    TRUE
)
FetchContent_GetProperties(kinet-labs_blake3_reference)
if(NOT kinet-labs_blake3_reference_POPULATED)
    FetchContent_Populate(kinet-labs_blake3_reference)
endif()

set(KINETCPP_BLAKE3_REFERENCE_SOURCE_DIR ${kinet-labs_blake3_reference_SOURCE_DIR}/c
    CACHE INTERNAL "Path to the kinet-labs/blake3-reference c/ directory (BLAKE3 reference C sources + header)")

# intx — extended-precision integer C++ library.
#
# Source:  github.com/kinet-labs/intx (kinet-labs-maintained fork of chfast/intx)
# Pinned:  v0.15.0
# License: Apache-2.0 (header from upstream LICENSE).
# Layout:  single-header (include/intx/intx.hpp).
#
# Pulled via FetchContent from kinet-labs/intx so the umbrella crypto/ tree
# stays self-contained at configure time without an in-tree copy of the
# upstream header. bn254, modexp cpp/ bodies #include <intx/intx.hpp>.
#
# Linking surface: `intx::intx` is an INTERFACE target. Consumers add it
# via target_link_libraries(<consumer> PRIVATE intx::intx). No symbols
# leak into the public ABI of the consuming static library because intx
# is header-only and template-instantiated at the call site.

include(FetchContent)

FetchContent_Declare(kinet-labs_intx
    GIT_REPOSITORY https://github.com/kinet-labs/intx.git
    GIT_TAG        v0.15.0
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(kinet-labs_intx)

# Define our own INTERFACE alias and point at the fetched header tree.
if(NOT TARGET intx::intx)
    add_library(intx INTERFACE)
    add_library(intx::intx ALIAS intx)
    target_compile_features(intx INTERFACE cxx_std_20)
    target_include_directories(intx INTERFACE
        $<BUILD_INTERFACE:${kinet-labs_intx_SOURCE_DIR}/include>
    )
endif()

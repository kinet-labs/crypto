# evmmax — modular arithmetic header for EVM-style precompiles.
#
# Source:  github.com/kinet-labs/evmmax (kinet-labs-maintained fork of ethereum/evmone)
# Pinned:  v0.21.0
# License: Apache-2.0 (header from upstream LICENSE).
# Layout:  single-header (lib/evmmax/evmmax.hpp upstream → re-exported as
#          <evmmax/evmmax.hpp> via include path).
#
# Pulled via FetchContent from kinet-labs/evmmax. evmmax provides the
# Montgomery-arithmetic ModArith template used by the bn254 / modexp
# first-party CPU bodies. It is header-only and depends transitively
# on intx (Montgomery multiplication uses intx::umul).

include(FetchContent)

FetchContent_Declare(kinet-labs_evmmax
    GIT_REPOSITORY https://github.com/kinet-labs/evmmax.git
    GIT_TAG        v0.21.0
    GIT_SHALLOW    TRUE
)
# Don't run upstream's CMake — we only want the evmmax header.
FetchContent_GetProperties(kinet-labs_evmmax)
if(NOT kinet-labs_evmmax_POPULATED)
    FetchContent_Populate(kinet-labs_evmmax)
endif()

if(NOT TARGET evmmax::evmmax)
    add_library(evmmax INTERFACE)
    add_library(evmmax::evmmax ALIAS evmmax)
    target_compile_features(evmmax INTERFACE cxx_std_20)
    # Upstream layout: <evmmax_SOURCE_DIR>/include/evmmax/evmmax.hpp
    # Consumers `#include <evmmax/evmmax.hpp>` so we add the include/ root.
    target_include_directories(evmmax INTERFACE
        $<BUILD_INTERFACE:${kinet-labs_evmmax_SOURCE_DIR}/include>
    )
    target_link_libraries(evmmax INTERFACE intx::intx)
endif()

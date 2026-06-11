# kzg — KZG polynomial commitments (EIP-4844 0x0a precompile + EL block-builder).
#
# Architecture:
#   * cpp/kzg.cpp implements verify_proof using the BLS12-381 pairing equation
#     directly (3 fixed scalars only — z, y, the trusted-setup G2 point [s]_2 is
#     hard-coded as a constant). No setup file required for that op.
#   * cpp/kzg_blob.cpp implements the four EL-side ops (blob_to_commit,
#     commit_to_proof, verify_blob, verify_blob_batch) by dispatching to the
#     vendored kinet-labs/c-kzg-4844 v2.1.7 (Apache-2 fork mirroring upstream
#     ethereum/c-kzg-4844 1:1). These ops require the 4096-element trusted
#     setup; we load it once at first use from a configure-time-embedded
#     copy of trusted_setup.txt.
#
# Vendoring (FetchContent — Path B):
#   * Pulls https://github.com/kinet-labs/c-kzg-4844 at refs/tags/v2.1.7.
#   * Compiles ckzg sources directly into a private static lib `ckzg_lib`.
#   * `ckzg_lib` carries undefined `_blst_*` references (U symbols) — same as
#     our own kzg.cpp body. Production cevm binaries never call the new ops
#     (they're EL-side, not EVM precompile surface), so the symbols stay
#     unresolved in the production link graph and the no-blst-in-production
#     invariant holds.
#   * `blst::oracle` is the test-time provider that resolves these references
#     when test executables link against kzg_cpu.

include(KinetAlgorithm)
include(FetchContent)

# Pull in the blst download via the existing test-oracle helper. blst is
# linked PRIVATE below so the consuming binary's symbol table does not
# expose blst to downstream production code.
include(${CMAKE_CURRENT_SOURCE_DIR}/../bls/test/cmake/blst.cmake)

# ---- kinet-labs/c-kzg-4844 v2.1.7 vendoring ---------------------------------------
# c-kzg-4844 ships no CMakeLists.txt. We vendor its sources at v2.1.7 and
# compile them ourselves with the blst include path. The blst static lib
# ships via blst::oracle (test-time only).
FetchContent_Declare(kinet-labs_c_kzg_4844
    GIT_REPOSITORY https://github.com/kinet-labs/c-kzg-4844.git
    GIT_TAG v2.1.7
)
FetchContent_GetProperties(kinet-labs_c_kzg_4844)
if(NOT kinet-labs_c_kzg_4844_POPULATED)
    FetchContent_Populate(kinet-labs_c_kzg_4844)
endif()

set(CKZG_SRC_DIR ${kinet-labs_c_kzg_4844_SOURCE_DIR}/src)
set(CKZG_BLST_INC ${BLST_ORACLE_INCLUDE_DIR})

# Compile the c-kzg-4844 sources we need for EIP-4844 (eip4844, common, setup).
# eip7594 (DAS / cells) is excluded — not required for the EIP-4844 ops.
add_library(ckzg_lib STATIC
    ${CKZG_SRC_DIR}/ckzg.c
    ${CKZG_SRC_DIR}/common/alloc.c
    ${CKZG_SRC_DIR}/common/bytes.c
    ${CKZG_SRC_DIR}/common/ec.c
    ${CKZG_SRC_DIR}/common/fr.c
    ${CKZG_SRC_DIR}/common/lincomb.c
    ${CKZG_SRC_DIR}/common/utils.c
    ${CKZG_SRC_DIR}/eip4844/blob.c
    ${CKZG_SRC_DIR}/eip4844/eip4844.c
    ${CKZG_SRC_DIR}/setup/setup.c
    # eip7594 deps required by setup.c's load_trusted_setup
    ${CKZG_SRC_DIR}/eip7594/fft.c
    ${CKZG_SRC_DIR}/eip7594/fk20.c
    ${CKZG_SRC_DIR}/eip7594/poly.c
    ${CKZG_SRC_DIR}/eip7594/recovery.c
    ${CKZG_SRC_DIR}/eip7594/cell.c
    ${CKZG_SRC_DIR}/eip7594/eip7594.c
)
target_include_directories(ckzg_lib PUBLIC
    ${CKZG_SRC_DIR}
    ${CKZG_BLST_INC}
)
set_target_properties(ckzg_lib PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    C_STANDARD 99
)
# blst is required as a build-time include path, but linking is deferred —
# tests pull blst::oracle, production never calls these ops.
add_dependencies(ckzg_lib blst_oracle)
# Quiet upstream warnings — this is a vendored Apache-2 third-party tree.
target_compile_options(ckzg_lib PRIVATE
    -Wno-unused-parameter
    -Wno-unused-but-set-variable
    -Wno-sign-compare
    -Wno-cast-qual
    -Wno-format
)

# ---- Embed trusted_setup.txt into a generated header -------------------------
# Configure-time: read the 8259-line trusted setup file shipped at v2.1.7 and
# emit it as a C++ string literal in trusted_setup.inc.h. The kzg_blob.cpp
# body fopens it via fmemopen() / tmpfile pipe so c-kzg-4844's
# load_trusted_setup_file(FILE*) can consume it without changing its signature.
set(KINET_KZG_TRUSTED_SETUP_FILE ${CKZG_SRC_DIR}/trusted_setup.txt)
set(KINET_KZG_TRUSTED_SETUP_INC ${CMAKE_CURRENT_BINARY_DIR}/trusted_setup.inc.h)

# Use file(READ ... HEX) to embed the file as a byte array. Robust across
# platforms vs xxd. The file is plain ASCII (~400 KB).
file(READ ${KINET_KZG_TRUSTED_SETUP_FILE} _setup_hex HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," _setup_bytes "${_setup_hex}")
file(SIZE ${KINET_KZG_TRUSTED_SETUP_FILE} _setup_size)
file(WRITE ${KINET_KZG_TRUSTED_SETUP_INC}
    "// Auto-generated from kinet-labs/c-kzg-4844 v2.1.7 src/trusted_setup.txt.\n"
    "// 4096 G1 Lagrange points + 65 G2 monomial points + 4096 G1 monomial points.\n"
    "// SPDX-License-Identifier: Apache-2.0\n"
    "#pragma once\n"
    "#include <cstddef>\n"
    "namespace kinet-labs::crypto::kzg {\n"
    "constexpr unsigned char TRUSTED_SETUP_BYTES[] = { ${_setup_bytes} };\n"
    "constexpr std::size_t TRUSTED_SETUP_SIZE = ${_setup_size};\n"
    "}  // namespace kinet-labs::crypto::kzg\n"
)
unset(_setup_hex)
unset(_setup_bytes)

# ---- kzg algorithm targets ---------------------------------------------------
# Two C-ABI shims:
#   * c-abi/c_kzg.cpp       — only `kzg_verify_proof` (EVM 0x0a precompile).
#                             Pulls cpp/kzg.cpp, no ckzg, no blst body.
#   * c-abi/c_kzg_blob.cpp  — three EL-side ops. Pulls cpp/kzg_blob.cpp +
#                             ckzg_lib + (transitively) blst.
# Splitting the C-ABI into two TUs keeps cevm's verify_proof path clean —
# the linker pulls only c_kzg.cpp.o into libevm, so blst stays unreferenced.
# Both TUs are compiled into the per-algorithm umbrella libraries; the
# `cevm_bls_kzg_canonical_cpu` adapter at cevm/lib/cevm_precompiles/
# compiles only c_kzg.cpp (not c_kzg_blob.cpp) to honour the invariant.
kinet_add_algorithm(
    NAME    kzg
    SOURCES cpp/kzg.cpp cpp/kzg_blob.cpp
    HEADERS cpp/kzg.hpp cpp/kzg_blob.hpp
    CABI    c-abi/c_kzg.cpp c-abi/c_kzg_blob.cpp
)

# kzg.cpp uses sha256 (canonical kinet-labs/crypto/sha256), intx, evmmax (deps),
# and blst (test-oracle helper, PRIVATE).
target_link_libraries(kzg_cpu PRIVATE
    intx::intx
    evmmax::evmmax
    blst::oracle
    sha256_cpu
    ckzg_lib
)
target_link_libraries(kzg PRIVATE
    intx::intx
    evmmax::evmmax
    blst::oracle
    sha256_cpu
    ckzg_lib
)
target_include_directories(kzg_cpu PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../sha256/cpp
    ${CMAKE_CURRENT_BINARY_DIR}
)
target_include_directories(kzg PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../sha256/cpp
    ${CMAKE_CURRENT_BINARY_DIR}
)

# Expose the vendored c-kzg-4844 test-vector tree to the EIP-4844 KAT test.
# Vectors path: ${kinet-labs_c_kzg_4844_SOURCE_DIR}/tests/<op>/kzg-mainnet/.
# 6 ops total, 253 cases (blob_to_commit=11, compute_blob=15, compute_kzg=52,
# verify_kzg=122, verify_blob=29, verify_blob_batch=24).
set(KINET_KZG_VECTORS_ROOT ${kinet-labs_c_kzg_4844_SOURCE_DIR}/tests
    CACHE INTERNAL "kinet-labs/c-kzg-4844 v2.1.7 KAT vectors root")

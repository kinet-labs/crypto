// SPDX-License-Identifier: Apache-2.0
//
// multiexp_doc_test.cpp -- Asserts the variable-time safety contract is
// physically present at the top of the `multi_scalar_mul` declaration in
// banderwagon/cpp/multiexp.hpp.
//
// This is a documentation regression guard. It exists because the algorithm
// is variable-time on the secret-scalar digit and the contract that prevents
// misuse is the comment block immediately preceding the function. Removing
// or weakening that block silently is a correctness regression even though
// the symbol itself still compiles.
//
// The test reads multiexp.hpp from the source tree and checks for every
// load-bearing marker phrase. It is a no-op compile check otherwise.
//
// MULTIEXP_HPP_PATH is provided by CMake as an absolute path so the test
// works under any build directory layout. If the macro is missing we fall
// back to a relative path that works when ctest runs from the build
// directory.

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

#ifndef MULTIEXP_HPP_PATH
#define MULTIEXP_HPP_PATH "../../banderwagon/cpp/multiexp.hpp"
#endif

namespace {

constexpr const char* kRequiredMarkers[] = {
    "VARIABLE-TIME",
    "Pippenger window method branches on scalar digit",
    "SAFE for verifier-side use (public scalars)",
    "UNSAFE for prover-side use with secret scalars",
    "Flush+Reload",
    "Callers MUST NOT pass secret blinding factors here",
    "scalar-blinding",
    "LP-137-FOLLOWUP-CT-MSM",
};

}  // namespace

int main() {
    std::ifstream in(MULTIEXP_HPP_PATH);
    if (!in.good()) {
        std::fprintf(stderr, "multiexp_doc_test: cannot open %s\n",
                     MULTIEXP_HPP_PATH);
        return 1;
    }
    std::stringstream buf;
    buf << in.rdbuf();
    const std::string contents = buf.str();

    int failed = 0;
    for (const char* marker : kRequiredMarkers) {
        if (contents.find(marker) == std::string::npos) {
            std::fprintf(stderr,
                         "multiexp_doc_test: missing required marker: %s\n",
                         marker);
            ++failed;
        }
    }
    if (failed != 0) {
        std::fprintf(stderr,
                     "multiexp_doc_test: %d required documentation marker(s) "
                     "missing from multiexp.hpp -- variable-time safety "
                     "contract has been weakened.\n",
                     failed);
        return 1;
    }
    return 0;
}

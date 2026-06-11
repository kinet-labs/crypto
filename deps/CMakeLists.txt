# kinet-labs/crypto/deps — external C++ dependencies (kinet-labs-maintained forks).
#
# Hard rules (per PHILOSOPHY.md):
#   * Only consume genuinely-external libraries here. First-party kinet-labs
#     headers stay in their canonical kinet-labs/<repo>/ home.
#   * Each library is INTERFACE / header-only when possible so it
#     instantiates at the call site and leaks zero symbols into the public
#     ABI of the consuming static library.
#   * Each library is pulled via FetchContent from a kinet-labs-maintained fork
#     pinned to a specific tag. NEVER track upstream HEAD.
#
# Currently consumed (all kinet-labs-maintained forks):
#   * intx              v0.15.0          github.com/kinet-labs/intx              Apache-2.0
#   * evmmax            v0.21.0          github.com/kinet-labs/evmmax            Apache-2.0
#   * pqclean           v0.0.1-kinet-labs    github.com/kinet-labs/pqclean           CC0
#   * ed25519-donna     v0.1.0-kinet-labs    github.com/kinet-labs/ed25519-donna     Public Domain
#   * blake3-reference  v1.5.0           github.com/kinet-labs/blake3-reference  CC0/Apache-2.0
#
# Consumed by:
#   * bn254/cpp/    — needs intx (uint256) + evmmax (ModArith Montgomery).
#   * modexp/cpp/   — needs intx (mul/udivrem) + evmmax (modinv).
#   * slhdsa/       — needs pqclean SPHINCS+ {sha2,shake}-{128,192,256}f-simple.
#   * ed25519/      — needs ed25519-donna (RFC 8032 reference).
#   * blake3/       — needs blake3-reference (portable C reference).
#
# bls/test/cmake/blst.cmake fetches kinet-labs/blst v0.3.15 for test-oracle only;
# it lives under bls/ rather than here because it is never linked into prod.

add_subdirectory(intx)
add_subdirectory(evmmax)
add_subdirectory(pqclean)
add_subdirectory(ed25519-donna)
add_subdirectory(blake3-reference)

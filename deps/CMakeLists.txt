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
#   * intx     v0.15.0  github.com/kinet-labs/intx     Apache-2.0
#   * evmmax   v0.21.0  github.com/kinet-labs/evmmax   Apache-2.0
#
# Consumed by:
#   * bn254/cpp/  — needs intx (uint256) + evmmax (ModArith Montgomery).
#   * modexp/cpp/ — needs intx (mul/udivrem) + evmmax (modinv).

add_subdirectory(intx)
add_subdirectory(evmmax)

# pqclean — Post-Quantum Cryptography clean reference implementations.
#
# Source:  github.com/kinet-labs/pqclean (kinet-labs-maintained snapshot of PQClean/PQClean)
# Pinned:  v0.0.1-kinet-labs
# License: CC0 1.0 (public domain). Each crypto_sign/<set>/clean/ tree carries
#          its own LICENSE pointer; common/* are also CC0.
# Layout:  full PQClean tree. Sources of interest:
#            common/{fips202,sha2,randombytes}.c
#            crypto_sign/sphincs-{sha2,shake}-{128,192,256}f-simple/clean/*.c
#            crypto_sign/ml-dsa-{44,65,87}/clean/*.c
#            crypto_kem/ml-kem-{512,768,1024}/clean/*.c
#
# Pulled via FetchContent from kinet-labs/pqclean. The kinet-labs/crypto algorithms
# (slhdsa, mldsa, mlkem) reference ${kinet-labs_pqclean_SOURCE_DIR} directly to
# build per-parameter-set OBJECT libraries with their own include scope -- this
# preserves the params.h-isolation pattern from the previous in-tree vendoring.
#
# This entry only fetches sources; it intentionally does NOT define any C
# targets. Each consumer (slhdsa/CMakeLists.txt, mldsa/CMakeLists.txt,
# mlkem/CMakeLists.txt) decides which parameter sets to compile and how.

include(FetchContent)

FetchContent_Declare(kinet-labs_pqclean
    GIT_REPOSITORY https://github.com/kinet-labs/pqclean.git
    GIT_TAG        v0.0.1-kinet-labs
    GIT_SHALLOW    TRUE
)
FetchContent_GetProperties(kinet-labs_pqclean)
if(NOT kinet-labs_pqclean_POPULATED)
    FetchContent_Populate(kinet-labs_pqclean)
endif()

# Re-export the source dir as a normalized cache var so consumers don't need to
# know the FetchContent name. Consumers reference ${KINETCPP_PQCLEAN_SOURCE_DIR}.
set(KINETCPP_PQCLEAN_SOURCE_DIR ${kinet-labs_pqclean_SOURCE_DIR}
    CACHE INTERNAL "Path to the kinet-labs/pqclean fetched source tree")

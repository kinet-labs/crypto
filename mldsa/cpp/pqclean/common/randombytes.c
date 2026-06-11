// =============================================================================
// PQClean randombytes - minimal getentropy(3) backend for kinet-labs
// =============================================================================
// Original PQClean randombytes.c carries a multi-OS dispatch tree (Linux
// getrandom, BSD arc4random, Windows CryptGenRandom, etc.) that does not
// detect macOS Darwin without an explicit -DBSD. kinet-labs builds for macOS
// (Apple Silicon dev) and Linux amd64 (production); both ship getentropy(3)
// (POSIX-2024 / glibc >= 2.25 / Darwin 10.12+). A single getentropy backend
// covers both with no preprocessor branches.
//
// SPDX-License-Identifier: MIT (PQClean upstream) + CC0
// Upstream attribution: Daan Sprenkels <hello@dsprenkels.com>
// =============================================================================

#include "randombytes.h"

#include <errno.h>
#include <unistd.h>

#if defined(__APPLE__)
#  include <sys/random.h>
#endif

int randombytes(uint8_t *output, size_t n) {
    // getentropy(3) caps each call at 256 bytes; loop for larger requests.
    while (n > 0) {
        size_t chunk = n > 256 ? 256 : n;
        if (getentropy(output, chunk) != 0) {
            return -1;
        }
        output += chunk;
        n -= chunk;
    }
    return 0;
}

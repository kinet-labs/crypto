// =============================================================================
// kinet-labs/crypto/pqclean_kat - C shim for the public KAT API
// =============================================================================
//
// Wraps PQClean's bare `randombytes` (renamed via randombytes.h macro to
// `PQCLEAN_randombytes`) into the uniquely-named `pqclean_kat_randombytes` so
// the KAT test never invokes a name that collides with the production
// randombytes signature.
//
// pqclean_kat_sha256 is provided directly by pqclean_kat_sha256.c -- a tiny
// FIPS 180-4 implementation private to this lib. Avoids dragging PQClean's
// full common/sha2.c (which collides with slhdsa_cpu's bundled copy).
// =============================================================================

#include "pqclean_kat.h"
#include "randombytes.h"   // -> #define randombytes PQCLEAN_randombytes

int pqclean_kat_randombytes(uint8_t *buf, size_t n) {
    return PQCLEAN_randombytes(buf, n);
}

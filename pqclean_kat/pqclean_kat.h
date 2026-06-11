// =============================================================================
// kinet-labs/crypto/pqclean_kat - shared support for deterministic NIST KAT tests
// =============================================================================
//
// Vendored verbatim from PQClean (CC0 / public domain) + SUPERCOP nistseed
// expansion (Bassham et al., NIST). Provides:
//
//   nist_kat_init(entropy[48], personalization|NULL, 256)
//       Seeds an AES-256-CTR DRBG with the given 48-byte entropy. After this
//       call every randombytes() invocation is deterministic.
//
//   randombytes(buf, n)  (-> PQCLEAN_randombytes via randombytes.h macro)
//       Pulls from the AES-CTR DRBG. Each call rotates the V counter and
//       updates the (Key,V) state per NIST SP 800-90A §10.2.
//
//   sha256(out[32], in, inlen)
//       Full one-shot SHA-256 (PQClean common/sha2.c).
//
// The KAT runner replicates PQClean's test/crypto_{sign,kem}/nistkat.c
// formatter byte-for-byte and compares the SHA-256 of its single (count=0)
// record against the upstream META.yml `nistkat-sha256` digest captured in
// pqclean_kat_digests.h.
//
// SPDX-License-Identifier: CC0-1.0 (PQClean) + BSD-3-Clause-Eco (kinet glue)
// =============================================================================

#ifndef KINET_PQCLEAN_KAT_H
#define KINET_PQCLEAN_KAT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// AES-256-CTR DRBG (PQClean nistkatrng.c).
void nist_kat_init(uint8_t *entropy_input,
                   const uint8_t *personalization_string,
                   int security_strength);

// PQClean's randombytes hook -- after nist_kat_init it pulls deterministic
// bytes from the AES-CTR DRBG. Header-renamed to avoid clashing with the
// production randombytes; tests call this name directly.
int pqclean_kat_randombytes(uint8_t *buf, size_t n);

// SHA-256 one-shot (PQClean common/sha2.c). Renamed from PQClean's bare
// `sha256` to avoid colliding with kinet-labs's public C-ABI int sha256(...).
void pqclean_kat_sha256(uint8_t *out, const uint8_t *in, size_t inlen);

#ifdef __cplusplus
}
#endif

#endif  // KINET_PQCLEAN_KAT_H

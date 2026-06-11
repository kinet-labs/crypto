// =============================================================================
// kinet-labs/crypto/pqclean_kat - upstream PQClean META.yml KAT digests
// =============================================================================
//
// SHA-256 digests of the canonical PQClean nistkat single-record output for
// each supported parameter set, captured verbatim from the PQClean repo
// (master, retrieved 2026-04-27):
//
//   crypto_sign/<scheme>/META.yml -> nistkat-sha256
//   crypto_kem/<scheme>/META.yml  -> nistkat-sha256
//
// The format hashed is the formatted-text output of test/crypto_sign/nistkat.c
// (or crypto_kem/nistkat.c) with entropy_input[48] = 0..47, count=0.
//
// These are the byte-equal-NIST acceptance values for our vendored
// PQClean reference implementation. See pqclean_kat.h for protocol details.
//
// To audit: `git -C <PQClean checkout> grep nistkat-sha256 -- crypto_*/<scheme>/META.yml`.
// =============================================================================

#ifndef KINET_PQCLEAN_KAT_DIGESTS_H
#define KINET_PQCLEAN_KAT_DIGESTS_H

#define PQCLEAN_NISTKAT_SHA256_MLDSA44   "9a196e7fb32fbc93757dc2d8dc1924460eab66303c0c08aeb8b798fb8d8f8cf3"
#define PQCLEAN_NISTKAT_SHA256_MLDSA65   "7cb96242eac9907a55b5c84c202f0ebd552419c50b2e986dc2e28f07ecebf072"
#define PQCLEAN_NISTKAT_SHA256_MLDSA87   "4537905d2aabcf302fab2f242baed293459ecda7c230e6a67063b02c7e2840ed"

#define PQCLEAN_NISTKAT_SHA256_MLKEM512  "c70041a761e01cd6426fa60e9fd6a4412c2be817386c8d0f3334898082512782"
#define PQCLEAN_NISTKAT_SHA256_MLKEM768  "5352539586b6c3df58be6158a6250aeff402bd73060b0a3de68850ac074c17c3"
#define PQCLEAN_NISTKAT_SHA256_MLKEM1024 "f580d851e5fb27e6876e5e203fa18be4cdbfd49e05d48fec3d3992c8f43a13e6"

#define PQCLEAN_NISTKAT_SHA256_SLHDSA_SHA2_128F  "cd1e13db3a56c0a6b3486a7b12bcddfda50cf5d1e4d14d3113e6456e969b8114"
#define PQCLEAN_NISTKAT_SHA256_SLHDSA_SHA2_192F  "fd4e301339b29ed5dc392c628d6c6db3d77a46ea61d16f7ff0e2b414f962f44c"
#define PQCLEAN_NISTKAT_SHA256_SLHDSA_SHA2_256F  "bd88b49453162a9b527e14228f037615d0fcbd13d24b48ece41ae1370ed13480"
#define PQCLEAN_NISTKAT_SHA256_SLHDSA_SHAKE_128F "46f4f87949dc994aa2b63b31c7307f44ca5ed025d7308ff408c8ba33473324dc"
#define PQCLEAN_NISTKAT_SHA256_SLHDSA_SHAKE_192F "60a9d2fd74adbef971a74477eca3170599beb4476d6428ced78b43b9641cc929"
#define PQCLEAN_NISTKAT_SHA256_SLHDSA_SHAKE_256F "f6d0825afeb4ce25943c974a0efde5659ceea927d2507b0ea1a92e092f536acd"

#endif  // KINET_PQCLEAN_KAT_DIGESTS_H

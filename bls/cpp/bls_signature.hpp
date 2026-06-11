// IRTF BLS12-381 signature primitive C++ surface.
// draft-irtf-cfrg-bls-signature-05, ciphersuite
// BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ — Ethereum consensus default,
// matches eth2-spec-tests, py_ecc, gnark-crypto, blst byte-for-byte.
//
// Pubkeys live on G1 (48-byte Zcash compressed). Signatures live on G2
// (96-byte Zcash compressed). Hash-to-G2 uses the SSWU map per RFC 9380
// with the proof-of-possession DST.
//
// Layering: bodies in bls_signature.cpp wrap blst (test-time oracle) the
// same way bls_pairing.cpp does. PRIVATE-link only — production
// libbls_cpu.a / libcevm_precompiles.a stay blst-free per LP-137.

#pragma once

#include <cstddef>
#include <cstdint>

namespace cevm::crypto::bls
{
// All return values: 0 on success, 1 on verification mismatch (verify
// family only), <0 on decode/length/null-pointer error.

int keygen(const uint8_t seed[32], uint8_t sk[32]) noexcept;
int sk_to_pk(const uint8_t sk[32], uint8_t pk[48]) noexcept;
int sign(const uint8_t sk[32], const uint8_t* msg, size_t msg_len, uint8_t sig[96]) noexcept;
int verify(const uint8_t pk[48], const uint8_t* msg, size_t msg_len, const uint8_t sig[96]) noexcept;
int aggregate_pubkeys(const uint8_t* pks, size_t n, uint8_t agg_pk[48]) noexcept;
int aggregate_sigs(const uint8_t* sigs, size_t n, uint8_t agg_sig[96]) noexcept;
int fast_aggregate_verify(const uint8_t* pks, size_t n,
                          const uint8_t* msg, size_t msg_len,
                          const uint8_t agg_sig[96]) noexcept;
int aggregate_verify_distinct(const uint8_t* pks, size_t n,
                              const uint8_t* msgs_flat, const size_t* msg_lens,
                              const uint8_t agg_sig[96]) noexcept;
}  // namespace cevm::crypto::bls

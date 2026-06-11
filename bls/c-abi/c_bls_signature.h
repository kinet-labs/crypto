// Brand-neutral C ABI for BLS12-381 IRTF signature primitives.
// IRTF draft-irtf-cfrg-bls-signature-05, ciphersuite
// BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ — Ethereum consensus default.
//
// Pubkeys live on G1 (48 bytes Zcash-compressed). Signatures live on G2
// (96 bytes Zcash-compressed). Hash-to-G2 uses the SSWU map per RFC 9380
// with the proof-of-possession DST (matches eth2-spec-tests).
//
// All return values: 0 on success, 1 on verification mismatch (verify
// family only), <0 on decode/length/null-pointer error.
//
// Layering: bodies live in cpp/bls_signature.cpp which PRIVATE-links blst
// (test-time oracle) the same way bls_pairing.cpp does. Production
// libbls_cpu.a stays blst-free per LP-137. Consumers that need real
// signatures link the bls_signature_oracle archive in addition.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// IRTF KeyGen (§2.3): HKDF-Extract+Expand from a 32-byte IKM with the
// BLS-SIG-KEYGEN-SALT salt, mod r. Output is the big-endian encoding of
// the secret scalar in [1, r).
int bls12_381_keygen(const uint8_t seed[32], uint8_t sk[32]);

// Derive the 48-byte compressed G1 pubkey from a 32-byte secret key.
int bls12_381_sk_to_pk(const uint8_t sk[32], uint8_t pk[48]);

// Sign msg with the 32-byte secret key. Output is 96-byte compressed G2.
int bls12_381_sign(const uint8_t sk[32],
                   const uint8_t* msg, size_t msg_len,
                   uint8_t sig[96]);

// Verify the 96-byte compressed signature against the 48-byte compressed
// pubkey and msg. Performs subgroup checks on both points.
int bls12_381_verify(const uint8_t pk[48],
                     const uint8_t* msg, size_t msg_len,
                     const uint8_t sig[96]);

// Aggregate n compressed pubkeys into a single compressed pubkey.
int bls12_381_aggregate_pubkeys(const uint8_t* pks, size_t n,
                                uint8_t agg_pk[48]);

// Aggregate n compressed signatures into a single compressed signature.
int bls12_381_aggregate_sigs(const uint8_t* sigs, size_t n,
                             uint8_t agg_sig[96]);

// FastAggregateVerify: n pubkeys all signed the same msg.
int bls12_381_fast_aggregate_verify(const uint8_t* pks, size_t n,
                                    const uint8_t* msg, size_t msg_len,
                                    const uint8_t agg_sig[96]);

// AggregateVerify with distinct messages per pubkey. msgs_flat is the
// concatenation of n messages; msg_lens[i] is the length of the i-th.
int bls12_381_aggregate_verify_distinct(const uint8_t* pks, size_t n,
                                        const uint8_t* msgs_flat,
                                        const size_t*  msg_lens,
                                        const uint8_t  agg_sig[96]);

#ifdef __cplusplus
}  // extern "C"
#endif

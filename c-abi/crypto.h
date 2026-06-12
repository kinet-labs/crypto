// =============================================================================
// kinet-labs/crypto - canonical public C ABI
// =============================================================================
//
// This is the single public C entry point for all algorithms in kinet-labs/crypto.
// Consumed by:
//   - kinet-labs/crypto (Go cgo)
//   - kinet-labs/kinet  (Go cgo)
//   - hanzoai/node (Go cgo)
//   - zooai/node   (Go cgo)
//   - any Rust caller (via bindgen)
//
// Naming: <alg>_<op> for everything in this header. The brand lives in the
// include path (<kinet/crypto/...>); symbols themselves are brand-neutral so
// downstream code reads as plain crypto.
//
// Backend selection: every operation runs on CPU by default. Set the global
// preferred GPU backend with crypto_gpu_set_default(); operations that can
// dispatch to GPU will check availability and fall back to CPU on miss.
//
// Wire status: this header advertises the C-ABI surface for every algorithm
// in the repo. Not every symbol has a CPU body wired yet — placeholders
// return CRYPTO_ERR_NOTIMPL with full nullptr argument validation. Use
// crypto_status() / crypto_alg_status(alg_bit) to detect at runtime which
// algorithms have wired bodies vs NOTIMPL placeholders before dispatching.
//
// Determinism (where wired): every CPU and GPU code path that returns
// CRYPTO_OK returns byte-identical output for any given input across all
// backends. This is a tested invariant for the wired algorithms (see
// <alg>/test/<alg>_determinism_test.cpp). Algorithms still in
// CRYPTO_ERR_NOTIMPL state make no determinism guarantee until wired.
//
// =============================================================================

#pragma once
#include <stddef.h>
#include <stdint.h>

// First-party algorithm-specific headers (declarations only). These also
// declare the same symbols this header exposes; including them keeps the
// canonical first-party header reachable as <kinet/crypto/<alg>.h> while the
// unified surface is reachable as <crypto.h>.
#include "kinet/crypto/keccak.h"     /* keccak256 */
#include "kinet/crypto/secp256k1.h"  /* secp256k1_ecrecover{,_verify,_batch} */
#include "kinet/crypto/attestation/attestation.h"  /* attestation_parse_{sev_snp,tdx,nv} */
#include "kinet/crypto/attestation/composite.h"    /* attestation_compute_composite_root */

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Return codes
// =============================================================================
//   0  -> success
//   1  -> verify success (boolean ops only); 0 means invalid signature
//  <0  -> failure (negated errno-ish)
// =============================================================================

#define CRYPTO_OK              0
#define CRYPTO_ERR_INPUT      -1
#define CRYPTO_ERR_LENGTH     -2
#define CRYPTO_ERR_VERIFY     -3
#define CRYPTO_ERR_BACKEND    -4
#define CRYPTO_ERR_NOTIMPL    -5
#define CRYPTO_ERR_INTERNAL   -6

// =============================================================================
// GPU control
// =============================================================================

#define CRYPTO_BACKEND_CPU   0
#define CRYPTO_BACKEND_CUDA  1
#define CRYPTO_BACKEND_METAL 2
#define CRYPTO_BACKEND_WGSL  3

// 1 if the backend is available, 0 otherwise.
int crypto_gpu_available(int backend);

// Sets the preferred backend for any operation that supports GPU acceleration.
// Returns CRYPTO_OK on success, CRYPTO_ERR_BACKEND if unavailable.
int crypto_gpu_set_default(int backend);

// Returns the active backend (one of CRYPTO_BACKEND_*).
int crypto_gpu_get_default(void);

// Returns library version as a static null-terminated string ("MAJOR.MINOR.PATCH").
const char* crypto_version(void);

// =============================================================================
// Wire status — runtime introspection
// =============================================================================
//
// crypto_status() returns a 64-bit bitmask: bit set ⇒ algorithm has a wired
// CPU body (calling its symbols can return CRYPTO_OK). Bit clear ⇒ all
// symbols return CRYPTO_ERR_NOTIMPL (after argument validation).
//
// Consumers MUST call crypto_status() at startup and route around any
// algorithm whose bit is clear, instead of relying on per-call NOTIMPL.
//
// Flag values are stable for the lifetime of the v1.x C-ABI.
// =============================================================================

#define CRYPTO_ALG_SHA256          (1ULL << 0)
#define CRYPTO_ALG_KECCAK256       (1ULL << 1)
#define CRYPTO_ALG_BLAKE2B         (1ULL << 2)
#define CRYPTO_ALG_BLAKE3          (1ULL << 3)
#define CRYPTO_ALG_RIPEMD160       (1ULL << 4)
#define CRYPTO_ALG_AEAD_CHACHA     (1ULL << 5)
#define CRYPTO_ALG_AEAD_AES_GCM    (1ULL << 6)
#define CRYPTO_ALG_SECP256K1       (1ULL << 7)   /* recover only; sign/verify still NOTIMPL */
#define CRYPTO_ALG_SECP256R1       (1ULL << 8)   /* verify wired (RIP-7212/EIP-7951) */
#define CRYPTO_ALG_ED25519         (1ULL << 9)
#define CRYPTO_ALG_SR25519         (1ULL << 10)  /* sign/verify wired (kinet-labs/sr25519-crust) */
#define CRYPTO_ALG_BN254           (1ULL << 11)  /* add/mul/pairing wired */
#define CRYPTO_ALG_BLS12_381       (1ULL << 12)  /* canonical bls12_381_* surface; legacy bls_* still NOTIMPL */
#define CRYPTO_ALG_KZG             (1ULL << 13)
#define CRYPTO_ALG_MLDSA           (1ULL << 14)
#define CRYPTO_ALG_MLKEM           (1ULL << 15)
#define CRYPTO_ALG_SLHDSA          (1ULL << 16)
#define CRYPTO_ALG_FROST           (1ULL << 17)  /* NOTIMPL */
#define CRYPTO_ALG_CGGMP21         (1ULL << 18)  /* setup/partial_sign wired; aggregate+verify host-side */
#define CRYPTO_ALG_RINGTAIL        (1ULL << 19)  /* NOTIMPL */
#define CRYPTO_ALG_IPA             (1ULL << 20)  /* modern create_proof/check_proof wired; legacy commit/verify NOTIMPL */
#define CRYPTO_ALG_LAMPORT         (1ULL << 21)
#define CRYPTO_ALG_PEDERSEN        (1ULL << 22)  /* vector + tree commit wired */
#define CRYPTO_ALG_POSEIDON_BN254  (1ULL << 23)
#define CRYPTO_ALG_POSEIDON_GLDLKS (1ULL << 24)
#define CRYPTO_ALG_VERKLE          (1ULL << 25)  /* NOTIMPL — IPA blocker */
#define CRYPTO_ALG_MODEXP          (1ULL << 26)
#define CRYPTO_ALG_EVM256          (1ULL << 27)
#define CRYPTO_ALG_NTT             (1ULL << 28)
#define CRYPTO_ALG_POLY_MUL        (1ULL << 29)
#define CRYPTO_ALG_BANDERWAGON     (1ULL << 30)
#define CRYPTO_ALG_ATTESTATION     (1ULL << 31)

// crypto_status returns a bitmask of the algorithms that have wired CPU
// bodies in this build. A bit is set when at least one operation in that
// algorithm can return a value other than CRYPTO_ERR_NOTIMPL after argument
// validation. Stable across the v1.x ABI.
uint64_t crypto_status(void);

// crypto_alg_status returns 1 iff the bit corresponding to alg_flag is set
// in crypto_status(). alg_flag must be exactly one CRYPTO_ALG_* value.
int crypto_alg_status(uint64_t alg_flag);

// =============================================================================
// Hashes
// =============================================================================

/* keccak256(in, in_len, out[32])  -- declared in <kinet/crypto/keccak.h> (void return). */
int sha256   (const uint8_t* in, size_t in_len, uint8_t out[32]);
int blake2b  (const uint8_t* in, size_t in_len, uint8_t out[64]);
int blake3   (const uint8_t* in, size_t in_len, uint8_t out[32]);
int ripemd160(const uint8_t* in, size_t in_len, uint8_t out[20]);

// Batch variants — n inputs of varying lengths, n outputs of fixed length.
int blake3_batch (const uint8_t* const* in, const size_t* in_len, size_t n, uint8_t* out_flat);
int keccak256_batch(const uint8_t* const* in, const size_t* in_len, size_t n, uint8_t* out_flat);

// =============================================================================
// AEAD (symmetric)
// =============================================================================

int aead_chacha20poly1305_seal(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct, uint8_t tag[16]);

int aead_chacha20poly1305_open(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    const uint8_t tag[16],
    uint8_t* pt);

// AES-256-GCM (NIST SP 800-38D). 96-bit IV only -- the FIPS-recommended
// length and the only one modern protocols (TLS 1.2/1.3, IPsec, JOSE) use.
int aead_aes_256_gcm_seal(
    const uint8_t key[32], const uint8_t iv[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct, uint8_t tag[16]);

int aead_aes_256_gcm_open(
    const uint8_t key[32], const uint8_t iv[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    const uint8_t tag[16],
    uint8_t* pt);

// =============================================================================
// EC signatures (classical)
// =============================================================================

// secp256k1 (Ethereum / Bitcoin)
int secp256k1_sign       (const uint8_t sk[32], const uint8_t msg32[32], uint8_t sig[64], uint8_t* recid);
int secp256k1_verify     (const uint8_t pk[64], const uint8_t msg32[32], const uint8_t sig[64]);
int secp256k1_recover    (const uint8_t msg32[32], const uint8_t sig[65], uint8_t pubkey[64]);
int secp256k1_sk_to_pk   (const uint8_t sk[32], uint8_t pk[64]);

// secp256r1 / NIST P-256
int secp256r1_verify     (const uint8_t pk[64], const uint8_t* msg, size_t msg_len, const uint8_t sig[64]);

// ed25519
int ed25519_keygen       (const uint8_t seed[32], uint8_t sk[32], uint8_t pk[32]);
int ed25519_sign         (const uint8_t sk[32], const uint8_t* msg, size_t msg_len, uint8_t sig[64]);
int ed25519_verify       (const uint8_t pk[32], const uint8_t* msg, size_t msg_len, const uint8_t sig[64]);

// sr25519 (Schnorrkel)
int sr25519_sign         (const uint8_t sk[32], const uint8_t* msg, size_t msg_len, uint8_t sig[64]);
int sr25519_verify       (const uint8_t pk[32], const uint8_t* msg, size_t msg_len, const uint8_t sig[64]);

// =============================================================================
// Pairings & BLS
// =============================================================================

// BN254 (alt_bn128) - EVM precompiles
int bn254_add            (const uint8_t in[128], uint8_t out[64]);
int bn254_mul            (const uint8_t in[96],  uint8_t out[64]);
int bn254_pairing        (const uint8_t* pairs,  size_t n_pairs, uint8_t out[32]);

// BLS12-381 (consensus)
int bls_keygen           (const uint8_t seed[32], uint8_t sk[32]);
int bls_sk_to_pk         (const uint8_t sk[32],   uint8_t pk[48]);
int bls_sign             (const uint8_t sk[32],   const uint8_t* msg, size_t msg_len, uint8_t sig[96]);
int bls_verify           (const uint8_t pk[48],   const uint8_t* msg, size_t msg_len, const uint8_t sig[96]);
int bls_aggregate_pubkeys(const uint8_t* pks, size_t n, uint8_t agg_pk[48]);
int bls_aggregate_sigs   (const uint8_t* sigs, size_t n, uint8_t agg_sig[96]);
int bls_aggregate_verify (const uint8_t* pks, const uint8_t* msg, size_t msg_len, const uint8_t agg_sig[96], size_t n);
int bls_batch_verify     (const uint8_t* pks, const uint8_t* msgs, size_t msg_len, const uint8_t* sigs, size_t n);

// =============================================================================
// KZG (EIP-4844)
// =============================================================================

int kzg_blob_to_commit   (const uint8_t blob[131072], uint8_t commit[48]);
int kzg_commit_to_proof  (const uint8_t blob[131072], const uint8_t z[32], uint8_t proof[48], uint8_t y[32]);
int kzg_verify_proof     (const uint8_t commit[48], const uint8_t z[32], const uint8_t y[32], const uint8_t proof[48]);
int kzg_verify_blob      (const uint8_t blob[131072], const uint8_t commit[48], const uint8_t proof[48]);

// =============================================================================
// Post-quantum
// =============================================================================
// Mode is the NIST level: 2 (Dilithium2/Kyber512/SLH-128s),
//                         3 (Dilithium3/Kyber768/SLH-192s),
//                         5 (Dilithium5/Kyber1024/SLH-256s).

int mldsa_keygen         (int mode, const uint8_t seed[32], uint8_t* pk, uint8_t* sk);
int mldsa_sign           (int mode, const uint8_t* sk, const uint8_t* msg, size_t msg_len, uint8_t* sig, size_t* sig_len);
int mldsa_verify         (int mode, const uint8_t* pk, const uint8_t* msg, size_t msg_len, const uint8_t* sig, size_t sig_len);

int mlkem_keygen         (int mode, const uint8_t seed[32], uint8_t* pk, uint8_t* sk);
int mlkem_encap          (int mode, const uint8_t* pk, uint8_t* ct, uint8_t ss[32]);
int mlkem_decap          (int mode, const uint8_t* sk, const uint8_t* ct, uint8_t ss[32]);

int slhdsa_keygen        (int mode, const uint8_t seed[32], uint8_t* pk, uint8_t* sk);
int slhdsa_sign          (int mode, const uint8_t* sk, const uint8_t* msg, size_t msg_len, uint8_t* sig, size_t* sig_len);
int slhdsa_verify        (int mode, const uint8_t* pk, const uint8_t* msg, size_t msg_len, const uint8_t* sig, size_t sig_len);

// =============================================================================
// Threshold
// =============================================================================

// Threshold context handle (opaque). Lifetime managed by *_destroy.
typedef struct frost_ctx     frost_ctx;
typedef struct cggmp21_ctx   cggmp21_ctx;
typedef struct ringtail_ctx  ringtail_ctx;

// FROST (threshold Schnorr)
int frost_setup          (uint32_t t, uint32_t n, frost_ctx** out);
int frost_partial_sign   (frost_ctx* ctx, const uint8_t* msg, size_t msg_len, uint32_t signer_id, uint8_t* partial);
int frost_aggregate      (frost_ctx* ctx, const uint8_t* partials, size_t n_partials, uint8_t sig[64]);
int frost_verify         (const uint8_t pk[32], const uint8_t* msg, size_t msg_len, const uint8_t sig[64]);
void frost_destroy       (frost_ctx* ctx);

// CGGMP21 (threshold ECDSA). Aggregation is host-side / network-bound and
// final ECDSA verification is plain secp256k1 (use secp256k1_verify); they
// are deliberately not exposed in the C-ABI.
int cggmp21_setup        (uint32_t t, uint32_t n, cggmp21_ctx** out);
int cggmp21_partial_sign (cggmp21_ctx* ctx, const uint8_t* msg, size_t msg_len, uint32_t signer_id, uint8_t* partial);
void cggmp21_destroy     (cggmp21_ctx* ctx);

// Ringtail (Ring-LWE threshold sig over R_q = Z_q[X]/(X^N+1)). See
// ringtail/cpp/ringtail.hpp for parameters (Q = 998244353, N = 512, K = L = 4).
//
// Two-pass length convention: pass sig_len pointing to the caller's buffer
// size; on CRYPTO_ERR_LENGTH (or sig == nullptr), *sig_len is rewritten with
// the required byte length. ringtail_pk_size() / ringtail_sig_size() are
// constants for the pinned parameter set.
int    ringtail_setup       (uint32_t t, uint32_t n, ringtail_ctx** out);
int    ringtail_sign        (ringtail_ctx* ctx, const uint8_t* msg, size_t msg_len, uint8_t* sig, size_t* sig_len);
int    ringtail_verify      (const uint8_t* pk, size_t pk_len, const uint8_t* msg, size_t msg_len, const uint8_t* sig, size_t sig_len);
int    ringtail_pk          (const ringtail_ctx* ctx, uint8_t* out_pk, size_t out_len);
size_t ringtail_pk_size     (void);
size_t ringtail_sig_size    (void);
void   ringtail_destroy     (ringtail_ctx* ctx);

// =============================================================================
// ZK primitives
// =============================================================================

// IPA (inner product argument)
int ipa_commit           (const uint8_t* coeffs, size_t n, uint8_t commit[48]);
int ipa_verify           (const uint8_t commit[48], const uint8_t* proof, size_t proof_len);

// Lamport one-time sigs
int lamport_keygen       (const uint8_t seed[32], uint8_t* pk, uint8_t* sk);
int lamport_sign         (const uint8_t* sk, const uint8_t msg32[32], uint8_t* sig);
int lamport_verify       (const uint8_t* pk, const uint8_t msg32[32], const uint8_t* sig);

// Pedersen vector commitments — see pedersen/c-abi/c_pedersen.cpp for the
// full surface (pedersen_generators_from_seed, pedersen_vector_commit,
// pedersen_vector_verify_open, pedersen_tree_commit).

// Pedersen tree-reduce vector commit at the fixed Verkle width N = 256.
// Single-shot variant of pedersen_vector_commit that the GPU backend can
// satisfy in one dispatch via threadgroup-cooperative tree reduction
// (saves log_2(256) = 8 host -> GPU round-trips). Always callable; falls
// back to the CPU reference when no GPU device is present.
//
//   scalars     : 256 * 32 bytes   -- raw BE Fr elements
//   blinding    : 32 bytes         -- raw BE Fr scalar
//   gens_g_xy   : 256 * 64 bytes   -- G_basis[i].x || .y in raw BE
//   gens_h_xy   : 64 bytes         -- H.x || H.y in raw BE
//   out_xy      : 64 bytes         -- commitment.x || .y in raw BE
//
// Returns CRYPTO_OK on success, CRYPTO_ERR_INPUT on null / bad input.
int pedersen_tree_commit (const uint8_t* scalars, const uint8_t blinding[32],
                          const uint8_t* gens_g_xy, const uint8_t gens_h_xy[64],
                          uint8_t out_xy[64]);

// Poseidon hash (Goldilocks + BN254/Fr variants)
int poseidon_goldilocks  (const uint8_t* in, size_t in_len, uint8_t out[32]);
int poseidon_bn254       (const uint8_t* in, size_t in_len, uint8_t out[32]);

// Verkle commitments (banderwagon)
int verkle_commit        (const uint8_t* coeffs, size_t n, uint8_t commit[32]);
int verkle_verify        (const uint8_t commit[32], const uint8_t* proof, size_t proof_len);

// =============================================================================
// EVM bigint math (precompiles)
// =============================================================================

// EIP-198: modular exponentiation
int modexp(const uint8_t* base, size_t base_len,
           const uint8_t* exp,  size_t exp_len,
           const uint8_t* mod,  size_t mod_len,
           uint8_t* out);

// Same as modexp() but forces the Karatsuba-Montgomery (SOS) inner loop for
// moduli ≥ 1024 bits (RSA-attestation lanes). Byte-identical output to
// modexp() for any input; the difference is interior multiplication strategy.
int modexp_karatsuba(const uint8_t* base, size_t base_len,
                     const uint8_t* exp,  size_t exp_len,
                     const uint8_t* mod,  size_t mod_len,
                     uint8_t* out);

// EVM 256-bit math primitives
int evm256_mulmod        (const uint8_t a[32], const uint8_t b[32], const uint8_t m[32], uint8_t out[32]);
int evm256_addmod        (const uint8_t a[32], const uint8_t b[32], const uint8_t m[32], uint8_t out[32]);

// =============================================================================
// NTT (used directly by FHE; exposed here as a primitive)
// =============================================================================

int ntt_forward          (uint64_t* coeffs, size_t n, uint64_t modulus, uint64_t root);
int ntt_inverse          (uint64_t* coeffs, size_t n, uint64_t modulus, uint64_t root_inv);

// Polynomial multiplication via NTT.
int poly_mul             (const uint64_t* a, const uint64_t* b, size_t n, uint64_t modulus, uint64_t root, uint64_t* out);

#ifdef __cplusplus
}  // extern "C"
#endif

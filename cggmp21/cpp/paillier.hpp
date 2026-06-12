// Paillier cryptosystem (Paillier 1999) at 2048-bit modulus, plus the
// CGGMP21 Π^enc sigma protocol (well-formedness range proof for a Paillier
// ciphertext), as required by the CGGMP21 round-1 pre-signing record.
//
// Paillier scheme (additive-homomorphic):
//
//   keygen :  pick safe primes p, q with |p| = |q| = 1024
//             N = p * q                       (2048-bit)
//             λ = lcm(p-1, q-1) = (p-1)(q-1)  (for safe primes the gcd is 2)
//             μ = (L( (1+N)^λ mod N^2 ))^{-1} mod N    where L(u) = (u-1)/N
//
//   encrypt :  enc_N(m, r) = (1+N)^m * r^N  mod N^2
//              with the binomial collapse  (1+N)^m ≡ 1 + m*N (mod N^2)
//              this becomes               (1 + m*N) * r^N mod N^2
//
//   decrypt :  m = L( c^λ mod N^2 ) * μ mod N
//
// All Z_{N^2} arithmetic is done with the 4096-bit Karatsuba modexp primitive
// shipped today (modexp/cpp/karatsuba.hpp + modexp/cpp/modexp.hpp); the
// modular reduction is performed by modexp_karatsuba() with exponent 1.
//
// Π^enc (CGGMP21 §6.1, simplified DCR-only form):
//
//   prover knows (k, ρ) such that K = enc_N(k, ρ),  k ∈ [0, 2^l)
//   commit  : α ← {0,1}^{l+ε}  ;  β ← Z_N^*  ;  A := enc_N(α, β)
//   chall   : e := SHA-256( N || N^2 || K || A ) mod 2^256
//   respond : z1 := α + e*k          (over Z, < 2^{l+ε+|e|})
//             z2 := β * ρ^e  mod N
//   verify  : enc_N(z1, z2) == A * K^e  (mod N^2)
//
// The aux-Pedersen "ring-Pedersen" variant in CGGMP21 §6.1 strengthens
// soundness against a maliciously-chosen aux modulus; for a single-party
// kernel where the verifier and prover share the same N and aux setup is
// out of scope, the bare DCR sigma proof is sound and is what the
// pre-signing kernel emits per slot.
//
// Wire format pinned by cggmp21/cpp/presign.hpp ::ZK_PI_ENC_BYTES:
//
//   uint8_t A   [PAILLIER_CTBYTES];      // 512 bytes, big-endian
//   uint8_t e   [32];                    // Fiat-Shamir challenge
//   uint8_t z1  [PAILLIER_BLINDBYTES];   // 256 bytes
//   uint8_t z2  [PAILLIER_BLINDBYTES];   // 256 bytes
//   uint8_t bind[32];                    // SHA-256(K||A||z1||z2) — freshness binder
//
// References:
//   - P. Paillier, "Public-Key Cryptosystems Based on Composite Degree
//     Residuosity Classes", EUROCRYPT 1999.
//   - R. Canetti et al., "UC Non-Interactive, Proactive, Threshold ECDSA
//     with Identifiable Aborts" (CGGMP21), eprint 2021/060, §A.6.

#pragma once

#include <cstddef>
#include <cstdint>

namespace kinet::crypto::cggmp21::paillier {

// Sizes — match cggmp21/cpp/presign.hpp.
constexpr std::size_t MOD_BYTES   = 256;   // |N|   = 2048 bits
constexpr std::size_t MOD_SQ_BYTES = 512;  // |N^2| = 4096 bits
constexpr std::size_t CT_BYTES    = 512;   // ciphertext lives in Z_{N^2}

// Public Paillier parameters (matches presign.hpp::PaillierKey layout).
struct PublicKey {
    uint8_t N   [MOD_BYTES];     // big-endian
    uint8_t N_sq[MOD_SQ_BYTES];  // big-endian, cached N^2
};

// Secret Paillier parameters — TEST PATH ONLY. Production kernels never see
// a full secret key on-chip; the kernel only encrypts and proves Π^enc, both
// of which use the public key alone.
struct SecretKey {
    PublicKey pk;
    uint8_t p     [MOD_BYTES / 2];   // 1024-bit
    uint8_t q     [MOD_BYTES / 2];
    uint8_t lambda[MOD_BYTES];       // = (p-1)(q-1) for safe primes
    uint8_t mu    [MOD_BYTES];       // = lambda^{-1} mod N
};

// === Keygen (test path) ============================================
//
// Deterministic 2048-bit Paillier key derivation from a 32-byte seed. Picks
// the smallest pair of probable primes p, q ≥ 2^1023 + seed-derived offsets
// that pass Miller-Rabin with 40 rounds (NIST SP 800-89 §5.4.1, MR-40 →
// error probability ≤ 2^-80). For test reproducibility only — production
// keygen lives in kinet/crypto/threshold/paillier_keygen.go.
//
// Returns 0 on success, -1 on input error.
int keygen_from_seed(const uint8_t seed[32], SecretKey& sk_out) noexcept;

// === Core operations ================================================

// Encrypt: ct = (1 + m*N) * r^N mod N^2.
// All inputs/outputs are big-endian byte arrays of fixed size.
//   m  : message in [0, 2^256)  — left-zero-padded into MOD_BYTES bytes.
//   r  : randomness ρ ∈ Z_N^*   — must be coprime to N (caller's responsibility).
//   ct : output buffer of CT_BYTES.
// Returns 0 on success, -1 on input error.
int encrypt(const PublicKey& pk,
            const uint8_t m_be[MOD_BYTES],
            const uint8_t r_be[MOD_BYTES],
            uint8_t       ct_out[CT_BYTES]) noexcept;

// Decrypt: m = L(c^λ mod N^2) * μ mod N. Test-only path; the production
// kernel never decrypts. Output is the recovered m, big-endian, MOD_BYTES.
int decrypt(const SecretKey& sk,
            const uint8_t     ct_be[CT_BYTES],
            uint8_t           m_out[MOD_BYTES]) noexcept;

// === Π^enc proof ====================================================
//
// Layout pinned by ZK_PI_ENC_BYTES in presign.hpp (1088 bytes total):
//   A[CT_BYTES] || e[32] || z1[MOD_BYTES] || z2[MOD_BYTES] || bind[32]
constexpr std::size_t PI_ENC_BYTES = CT_BYTES + 32 + MOD_BYTES + MOD_BYTES + 32;

// Prove: K = enc_N(k, ρ) is well-formed; emit the sigma transcript.
//   pk     : the encrypting party's Paillier public key
//   K      : the ciphertext under inspection (big-endian, CT_BYTES)
//   k_be   : witness, big-endian, MOD_BYTES (zero-extended from 32-byte
//            ECDSA scalar in the cggmp21 caller)
//   rho_be : witness randomness ρ used to form K, big-endian, MOD_BYTES
//   alpha_be, beta_be: prover-supplied randomness for the commitment
//                      (must be re-derived deterministically per slot in the
//                       cggmp21 kernel; not nondeterministic).
//   proof_out : PI_ENC_BYTES output buffer.
// Returns 0 on success, -1 on input error.
int pi_enc_prove(const PublicKey& pk,
                 const uint8_t K_be    [CT_BYTES],
                 const uint8_t k_be    [MOD_BYTES],
                 const uint8_t rho_be  [MOD_BYTES],
                 const uint8_t alpha_be[MOD_BYTES],
                 const uint8_t beta_be [MOD_BYTES],
                 uint8_t       proof_out[PI_ENC_BYTES]) noexcept;

// Verify: returns 0 if accept, +1 if reject, -1 on input error.
//   - Recomputes e := SHA-256(N || N^2 || K || A).
//   - Checks enc_N(z1, z2) == A * K^e (mod N^2).
//   - Checks bind tag == SHA-256(K || A || z1 || z2).
int pi_enc_verify(const PublicKey& pk,
                  const uint8_t K_be     [CT_BYTES],
                  const uint8_t proof_in [PI_ENC_BYTES]) noexcept;

}  // namespace kinet::crypto::cggmp21::paillier

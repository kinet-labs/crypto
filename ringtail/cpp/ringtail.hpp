// Ringtail — first-party Ring-LWE threshold signature.
//
// =============================================================================
// SCOPE
// =============================================================================
//
// Ringtail is the family of lattice threshold signature schemes implemented in
// the Kinet stack. The Go reference at github.com/kinet-labs/ringtail wraps the
// taurusgroup-style multi-party-sig protocol over the Lattigo ring layer
// (`kinet-labs/lattice/v7`), with parameters tuned for a 2-round network protocol
// (Q=0x1000000004A01 / N=256, σ_e=6.1, σ*=2^37, σ_u=2^27, MAC-authenticated
// rounds, full-rank check, BigInt L2-norm post-condition).
//
// This C++ body is the *single-process* shape of the same algebraic primitive:
//
//   - Same ring family R_q = Z_q[X]/(X^N + 1) (negacyclic NTT-friendly).
//   - Same Schnorr-Lyubashevsky structure with rejection sampling.
//   - Same threshold (t,n) topology — Shamir-shared signing key over R_q with
//     Lagrange reconstruction at the canonical evaluation point.
//
// Differences from the network-protocol Go reference (documented; not bugs):
//
//   - Single ringtail_ctx holds all n shares; the C-ABI is a one-process API.
//     The 2-round MAC-authenticated network exchange (D matrix broadcast,
//     z-share broadcast, full-rank check) is out of scope here — those bits
//     live in the Go networking layer (kinet-labs/threshold/protocols/ringtail/{
//     keygen,sign}/round*.go) and are not a property of the lattice math.
//   - Ring parameters use kinet-labs's own NTT prime Q = 998244353 with N = 512.
//     This is the same NTT-friendly prime the rest of kinet-labs/crypto uses
//     (ntt/, poly_mul/) so we share one Cooley-Tukey context across the
//     whole library. The Go reference's 48-bit prime is a Lattigo-internal
//     choice for Module-LWE batch parallelism — irrelevant for the
//     correctness contract this C-ABI exports.
//   - Discrete Gaussian sampler uses σ = 1.7 (per task brief and per-coef
//     rejection-sampling Karney method). Matches Falcon-class sampling
//     literature; well above the smoothing parameter for N = 512 / Q.
//
// =============================================================================
// PARAMETERS
// =============================================================================
//
//   q       = 998244353         (~30 bits; reuses ntt::Q)
//   N       = 512                (polynomial degree, R_q = Z_q[X]/(X^N+1))
//   l       = 4                  (signing-key dimension, vector of polys)
//   k       = 4                  (commitment dimension, height of A)
//   sigma   = 1.7                (Gaussian std-dev for s, e, y)
//   tau     = 30                 (challenge poly Hamming weight, c ∈ {-1,0,1})
//   B_inf   = q/4                (max ||z||_∞ for verification)
//
// Public key  : A (k×l polys) ‖ b (k polys)                 ( (k*l + k) * N * 4 bytes )
// Signature   : c (1 poly) ‖ z (l polys)                    ( (1 + l) * N * 4 bytes )
//
// Per-coefficient wire format: little-endian uint32_t (q < 2^30 so it fits).
//
// =============================================================================
// THRESHOLD
// =============================================================================
//
// (t,n)-Shamir over R_q at evaluation points x_i = i + 1 (i = 0..n-1).
// The signing key vector s is shared component-wise: each s_j ∈ R_q is
// reconstructed by summing λ_i(0) * share_i,j over any t shares. Lagrange
// coefficients λ_i(0) live in Z_q (constants, not polys) — same as the Go
// reference's ComputeLagrangeCoefficients but evaluated at x = 0.
//
// =============================================================================
// SECURITY NOTES
// =============================================================================
//
// * Rejection sampling loops only on ‖z‖_∞ check (a public condition); no
//   secret-dependent branching — constant-time on the signing path modulo the
//   public reject statistic.
// * KMS handles the at-rest secret-share storage; ringtail_ctx is opaque to
//   the caller and freed via ringtail_destroy.
// * Determinism: given a fixed setup seed and fixed signing-time RNG output,
//   the signature is byte-identical across all backends. See
//   ringtail/test/ringtail_test.cpp KAT vectors.
//
// =============================================================================

#ifndef CRYPTO_RINGTAIL_HPP
#define CRYPTO_RINGTAIL_HPP

#include <cstdint>
#include <cstddef>
#include <vector>

namespace kinet::crypto::ringtail {

// ---- Algebra parameters ---------------------------------------------------

inline constexpr uint64_t Q       = 998244353ULL;   // ntt::Q (Cyclone-FFT prime)
inline constexpr uint32_t N       = 512;             // poly degree, X^N + 1
inline constexpr uint32_t L       = 4;               // signing-key dim
inline constexpr uint32_t K       = 4;               // commitment dim
inline constexpr uint32_t TAU     = 30;              // challenge weight
inline constexpr uint64_t B_INF   = Q / 4;           // verify bound on ||z||_inf
inline constexpr double   SIGMA   = 1.7;             // Gaussian sigma
inline constexpr int32_t  GAUSS_BOUND = 12;          // |x| <= 12*sigma ⇒ effectively zero
                                                     // tail beyond ~7σ for σ=1.7

// ---- Wire sizes (bytes) ---------------------------------------------------

inline constexpr size_t POLY_BYTES = static_cast<size_t>(N) * 4;             // 2048
inline constexpr size_t PK_BYTES   = (K * L + K) * POLY_BYTES;               // 40960 for K=L=4
inline constexpr size_t SIG_BYTES  = (1 + L) * POLY_BYTES;                   // 10240 for L=4

// ---- Polynomial type (one element of R_q in standard form, [0, Q)). ------

using Poly = std::vector<uint64_t>;   // size == N

// ---- Key share for one party ---------------------------------------------

struct KeyShare {
    uint32_t party_id = 0;          // 1-based Shamir evaluation point.
    std::vector<Poly> s_share;       // length L; share of secret vector s at x = party_id.
};

// ---- Context (opaque to the caller; created by ringtail_setup) -----------

struct Context {
    uint32_t t = 0;                  // threshold
    uint32_t n = 0;                  // total parties
    std::vector<std::vector<Poly>> A; // K x L matrix of polys (NTT-domain)
    std::vector<Poly> b;             // length K vector of polys (NTT-domain)
    std::vector<KeyShare> shares;    // length n
    std::vector<uint8_t> seed;       // 32-byte seed used for setup; pinned for KAT determinism
    uint64_t sign_counter = 0;       // monotonically increases per Sign call (signing-time RNG seed input)
};

// ---- Public API -----------------------------------------------------------

// Setup generates a fresh (t,n) Ringtail context. seed must be 32 bytes; it
// determines all randomness in setup so KAT vectors can pin the output. If
// seed_len == 0, a system entropy seed is drawn.
//
// Returns CRYPTO_OK on success. Caller owns *out and must free via
// ringtail_destroy.
int Setup(uint32_t t, uint32_t n, const uint8_t* seed, size_t seed_len,
          Context** out);

// Sign produces a single-process threshold signature on msg. Internally:
//   1. Reconstructs s from the first t shares (Lagrange at x=0).
//   2. Runs Schnorr-Lyubashevsky with rejection sampling.
//   3. Serializes (c, z) into sig (must be at least SIG_BYTES).
//
// If sig is null OR *sig_len < SIG_BYTES, sets *sig_len = SIG_BYTES and
// returns CRYPTO_ERR_LENGTH (canonical "ask first" pattern).
//
// Signing-time RNG is seeded from H(ctx.seed || ctx.sign_counter) so any two
// distinct calls produce distinct signatures and the test suite can drive
// a deterministic seed schedule.
int Sign(Context* ctx,
         const uint8_t* msg, size_t msg_len,
         uint8_t* sig, size_t* sig_len);

// Verify checks that sig is a valid Ringtail signature on msg under pk.
// Returns CRYPTO_OK if valid, CRYPTO_ERR_VERIFY if invalid, CRYPTO_ERR_LENGTH
// on size mismatch.
int Verify(const uint8_t* pk, size_t pk_len,
           const uint8_t* msg, size_t msg_len,
           const uint8_t* sig, size_t sig_len);

// SerializePK fills out_pk with the canonical pk wire-format representation
// of the context's group public key (A || b). Caller must provide a buffer
// of length PK_BYTES. Returns CRYPTO_OK on success.
int SerializePK(const Context* ctx, uint8_t* out_pk);

// Destroy frees a context.
void Destroy(Context* ctx);

}  // namespace kinet::crypto::ringtail

#endif  // CRYPTO_RINGTAIL_HPP

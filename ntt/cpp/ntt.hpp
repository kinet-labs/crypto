// Number-Theoretic Transform over the Cyclone-FFT prime
//
//   Q = 998244353 = 119 * 2^23 + 1   (2-adicity 23, supports N up to 2^23)
//
// Mirrors the Go reference at github.com/kinet-labs/crypto/poly_mul (NTTForward /
// NTTInverse). Per-coefficient byte output is identical to the Go reference
// for any input — see kinet-labs/crypto/{ntt,poly_mul}/test/vectors/.
//
// =============================================================================
// DOMAIN CONVENTIONS — read this carefully (see #121 retro)
// =============================================================================
//
//   STANDARD     — values in [0, Q). What you usually mean by "x mod Q".
//   MONTGOMERY   — REDC-domain encoding x_mont = x * R mod Q with R = 2^32.
//
// Public API contract:
//   * Inputs (`uint64_t* a`)  : STANDARD form, in [0, 2^64), reduced mod Q.
//   * Outputs                 : STANDARD form, guaranteed in [0, Q).
//
// Internal hot-loop:
//   * `a[]` STANDARD throughout the butterfly.
//   * Twiddles in `Context::tw_fwd` / `tw_inv` are MONTGOMERY.
//   * `mont_mul(a_std, w_mont)` returns standard form (Lattigo direction).
//
// Generic-prime (`*_generic`) C-ABI path: standard form via 128-bit-mul
// mulmod. Slower but correct for any prime modulus + caller-supplied root.
//
// =============================================================================
// MONTGOMERY CONSTANTS (Q = 998244353, R = 2^32)
// =============================================================================
//
//   R          = 2^32 = 4294967296
//   R mod Q    = 301989884       (Mont representation of 1)
//   R^2 mod Q  = 932051910       (used by to_mont)
//   -Q^-1 mod R= 998244351       (used by REDC)

#ifndef CRYPTO_NTT_HPP
#define CRYPTO_NTT_HPP

#include <cstdint>
#include <vector>

namespace kinet::crypto::ntt {

// Cyclone-FFT prime: 119 * 2^23 + 1.
inline constexpr uint64_t Q = 998244353ULL;

// Generator of F_Q* (3 is a primitive root of F_Q).
inline constexpr uint64_t G = 3ULL;

// Largest log2(n) supported. Q's 2-adicity is 23; we cap at 16 (n=65536).
inline constexpr uint32_t MAX_LOG_N = 16;

// PRIMITIVE_ROOT is a 2^MAX_LOG_N-th primitive root of unity in F_Q.
// 3^((Q-1)/2^MAX_LOG_N) mod Q = 629671588.
// Same constant as the Go reference's poly_mul.PrimitiveRoot.
inline constexpr uint64_t PRIMITIVE_ROOT = 629671588ULL;

// Montgomery domain (R = 2^32).
inline constexpr uint32_t MONT_R_BITS    = 32;
inline constexpr uint64_t MONT_R_MASK    = (1ULL << MONT_R_BITS) - 1ULL;
inline constexpr uint64_t MONT_R_MOD_Q   = 301989884ULL;
inline constexpr uint64_t MONT_R2_MOD_Q  = 932051910ULL;
inline constexpr uint64_t MONT_Q_INV32   = 998244351ULL;

// Pre-computed Cooley-Tukey twiddle context.
//   tw_fwd[s-1] = wm_fwd in Montgomery form, where wm_fwd = omega^(n/2^s)
//   tw_inv[s-1] = wm_inv in Montgomery form (inverse direction)
//   inv_n_mont  = n^-1 mod Q in Montgomery form (for INTT 1/n scaling)
struct Context {
    uint32_t              n      = 0;
    uint32_t              log_n  = 0;
    std::vector<uint64_t> tw_fwd;
    std::vector<uint64_t> tw_inv;
    uint64_t              inv_n_mont = 0;
};

// Build a context for the given power-of-two n in [1, 2^MAX_LOG_N].
// Throws std::invalid_argument on bad n. O(log n) work.
Context make_context(uint32_t n);

// Forward NTT in place. n must equal ctx.n.
void forward(uint64_t* a, uint32_t n, const Context& ctx);

// Inverse NTT in place (includes 1/n scaling). n must equal ctx.n.
void inverse(uint64_t* a, uint32_t n, const Context& ctx);

// Generic-prime path. Returns false on malformed input.
bool forward_generic(uint64_t* a, uint32_t n, uint64_t q, uint64_t omega);
bool inverse_generic(uint64_t* a, uint32_t n, uint64_t q, uint64_t omega_inv);

// Square-and-multiply pow_mod (mod q). Used by tests and poly_mul.
uint64_t pow_mod(uint64_t base, uint64_t exp, uint64_t q);

}  // namespace kinet::crypto::ntt

#endif  // CRYPTO_NTT_HPP

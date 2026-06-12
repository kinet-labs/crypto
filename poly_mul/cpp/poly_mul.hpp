// Polynomial multiplication over Z_Q[X]/(X^n + 1) where Q = 998244353.
//
// NEGACYCLIC convolution (X^n = -1) — the lattice-crypto shape (ML-KEM,
// ML-DSA, Ringtail), NOT cyclic.
//
// Algorithms:
//   * Schoolbook  O(n^2)         — always correct, fastest below n = 64
//   * NTT-based   O(n log n)     — negacyclic via psi=2n-th-root pre/post
//
// Crossover: schoolbook wins below n = 64. Matches the Go reference's `Mul`.
//
// Domain conventions:
//   * Inputs and outputs are STANDARD form (NOT Montgomery).
//   * Inputs may be in [0, 2^64); reduced mod Q on entry.
//   * Outputs are guaranteed in [0, Q).
//   * NTT path uses ntt.hpp's Cyclone-FFT context (Mont-form twiddles
//     internally) but exposes only standard-form values at the boundary.

#ifndef CRYPTO_POLY_MUL_HPP
#define CRYPTO_POLY_MUL_HPP

#include <cstdint>

namespace kinet::crypto::poly_mul {

inline constexpr uint64_t Q = 998244353ULL;
inline constexpr uint32_t SCHOOLBOOK_THRESHOLD = 64;

// multiply: dispatcher. result[0..n) = a[0..n) * b[0..n) in Z_Q[X]/(X^n+1).
// na must equal nb. Returns false on malformed input.
bool multiply(uint64_t* result,
              const uint64_t* a, uint32_t na,
              const uint64_t* b, uint32_t nb);

bool multiply_schoolbook(uint64_t* result,
                         const uint64_t* a, uint32_t n,
                         const uint64_t* b);

// NTT path. Requires power-of-2 n with 2 <= n <= 2^15.
bool multiply_ntt(uint64_t* result,
                  const uint64_t* a, uint32_t n,
                  const uint64_t* b);

}  // namespace kinet::crypto::poly_mul

#endif  // CRYPTO_POLY_MUL_HPP

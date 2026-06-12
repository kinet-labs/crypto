// Six-step (factor-into-2D) NTT for large N > 2^16.
//
// Cooley-Tukey at radix 2 hits a memory-bandwidth ceiling above 2^16 because
// uncoalesced loads + thread divergence dominate. Factor N = N1 * N2 and run:
//
//   1. Reshape input as N1 x N2 row-major matrix.
//   2. NTT each column (size N1).
//   3. Multiply by twiddle factor omega^(i*j).
//   4. Transpose -> N2 x N1.
//   5. NTT each row (size N2).
//   6. (Output stays in transposed layout for downstream consumers.)
//
// For N = 2^20 with N1 = N2 = 2^10 each sub-NTT fits in L1 (8 KB). The
// transpose at step 4 is the only memory-bandwidth hit; all other steps
// stream linearly.
//
// Two flavors:
//
//   PRIME modulus q (q is prime, q ≡ 1 (mod N), 2N | q-1):
//       64-bit operands, __uint128_t intermediate, % q at the bottleneck.
//       Caller supplies primitive 2N-th root of unity in F_q.
//
//   POWER-OF-TWO modulus q = 2^64 (TFHE):
//       Machine-word arithmetic. Modular reduction is free (truncation).
//       Caller supplies a 2N-th root of unity mod 2^64. Such a root must
//       exist (the multiplicative group (Z/2^64)* has elements of order N
//       for any N | 2^62, and we satisfy this for any N <= 2^20).
//
// Determinism contract:
//   * For the PRIME path, output is byte-identical across CPU/CUDA/Metal/WGSL.
//   * For the POW2 (q=2^64) path, output is byte-identical across all
//     backends because every reduction is machine-word truncation.
//
// Dispatch is performed inside `ntt/c-abi/c_ntt.cpp` based on N.

#ifndef CRYPTO_NTT_LARGE_HPP
#define CRYPTO_NTT_LARGE_HPP

#include <cstdint>
#include <vector>

namespace kinet::crypto::ntt::large {

// Largest log2(N) supported by the six-step path. Bounded by available host
// RAM (2^20 * 8 B = 8 MiB per polynomial) and by the 2-adicity of any
// supported prime. The Cyclone-FFT prime Q = 119 * 2^23 + 1 has 2-adicity 23
// so 2^20 is comfortably within its native domain.
inline constexpr uint32_t MAX_LOG_N = 20;

// Sentinel: q = 0 is not a valid modulus, so callers use it to mean
// "modulus is 2^64; reduce by machine-word truncation".
inline constexpr uint64_t Q_POW2_64 = 0ULL;

// Precomputed twiddles for one (N, q, omega) triple. The CPU body owns the
// allocation so GPU drivers can borrow it via a const pointer.
struct LargeContext {
    uint32_t              n      = 0;        // total size (must equal N1 * N2)
    uint32_t              n1     = 0;        // column dimension
    uint32_t              n2     = 0;        // row dimension
    uint32_t              log_n1 = 0;
    uint32_t              log_n2 = 0;
    uint64_t              q      = 0;        // 0 means q = 2^64 (truncation)
    uint64_t              omega  = 0;        // 2N-th primitive root of unity
    // Per-stage twiddles for the inner radix-2 sub-NTTs. tw_inner[s-1] holds
    // the s-th-stage step root (omega_inner^(N/2^s) where omega_inner is the
    // chosen primitive root for the sub-transform).
    std::vector<uint64_t> tw_col_fwd;        // size = log_n1
    std::vector<uint64_t> tw_col_inv;        // size = log_n1
    std::vector<uint64_t> tw_row_fwd;        // size = log_n2
    std::vector<uint64_t> tw_row_inv;        // size = log_n2
    // Diagonal twiddle table: omega^(i*j) for 0 <= i < N1, 0 <= j < N2.
    // Layout: [i * N2 + j] in forward direction; inverse uses omega^(-i*j).
    std::vector<uint64_t> diag_fwd;          // size = N
    std::vector<uint64_t> diag_inv;          // size = N
    // Final-step normalisation for the inverse: N^(-1) mod q. For q = 2^64
    // this is the multiplicative inverse of N modulo 2^64, well-defined for
    // any odd power of two -- which N never is, so the q=2^64 path requires
    // N = 2^k where k <= 62 and we use the closed-form inverse of 2.
    uint64_t              n_inv  = 0;
};

// Build a context for the given (N, q, omega).
//   N must be a power of two with log_2(N) in (16, MAX_LOG_N].
//   For q != 0: q must be prime, q ≡ 1 (mod 2N), omega is a 2N-th
//     primitive root of unity in F_q.
//   For q == 0: modulus is 2^64; omega is a 2N-th root of unity mod 2^64.
//
// Throws std::invalid_argument on a malformed (N, q, omega) tuple.
LargeContext make_context(uint32_t n, uint64_t q, uint64_t omega);

// Forward NTT in place. Output is in transposed N2 x N1 row-major order
// (this is the natural layout coming out of step 5; downstream consumers
// either operate in this domain or call inverse() to round-trip).
void forward(uint64_t* a, const LargeContext& ctx);

// Inverse NTT in place. Accepts data in transposed (N2 x N1) layout, returns
// it in the original N-element vector layout. Includes 1/N scaling.
void inverse(uint64_t* a, const LargeContext& ctx);

// Helper: pick a balanced factorisation N = N1 * N2 minimising |log N1 - log N2|.
void pick_factors(uint32_t n, uint32_t& n1, uint32_t& n2);

}  // namespace kinet::crypto::ntt::large

#endif  // CRYPTO_NTT_LARGE_HPP

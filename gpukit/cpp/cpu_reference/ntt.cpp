// Number-theoretic transform (NTT) -- CPU reference, parametric over modulus.
//
// Two prime moduli ship: Kyber (q=3329) and Dilithium (q=8380417). Both use
// negacyclic NTT (multiplication mod x^n + 1).
//
// We compute everything in canonical form [0, q), no Montgomery; the values
// are small (32-bit) and the speed difference does not matter for the CPU
// reference -- correctness and byte-equality with GPU dispatches is what
// matters here.
//
// Forward transform uses a Cooley-Tukey decimation-in-time butterfly with
// precomputed powers of the primitive (2n)-th root of unity (zeta), in
// bit-reversed order. Inverse transform uses Gentleman-Sande and multiplies
// by n^-1 mod q at the end. Negacyclic-mul-then-NTT runs:
//   forward(a) -> a_hat
//   forward(b) -> b_hat
//   pointwise: c_hat = a_hat * b_hat * zeta^(odd) ... (we use the simplified
//              variant: forward both, pointwise multiply, inverse). For the
//              negacyclic case we precondition by zeta^(2i+1) folded in the
//              bit-reversed table -- which is the standard NewHope/Kyber
//              construction. The reference here uses the "schoolbook over the
//              quotient ring" approach: compute c[k] = sum a[i]*b[j] where
//              i+j = k or i+j = k+n with sign flip. This is O(n^2) but
//              perfectly correct, and that is what the CPU reference is for.
//   For the GPU kernels we will use the optimized NTT pointwise approach,
//   verified byte-equal against this O(n^2) reference.

#include "kinet/gpukit/ntt.h"
#include "kinet/gpukit/gpukit.h"
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

inline int32_t mod_q(int64_t x, int32_t q) {
    int64_t r = x % q;
    if (r < 0) r += q;
    return (int32_t)r;
}

inline int32_t add_q(int32_t a, int32_t b, int32_t q) {
    int32_t r = a + b;
    if (r >= q) r -= q;
    return r;
}

inline int32_t sub_q(int32_t a, int32_t b, int32_t q) {
    int32_t r = a - b;
    if (r < 0) r += q;
    return r;
}

inline int32_t mul_q(int32_t a, int32_t b, int32_t q) {
    return (int32_t)(((int64_t)a * b) % q);
}

inline int32_t pow_q(int32_t base, int32_t exp, int32_t q) {
    int32_t r = 1;
    base = mod_q(base, q);
    while (exp > 0) {
        if (exp & 1) r = mul_q(r, base, q);
        base = mul_q(base, base, q);
        exp >>= 1;
    }
    return r;
}

inline int32_t inv_q(int32_t a, int32_t q) {
    // Fermat: a^(q-2) mod q.
    return pow_q(a, q - 2, q);
}

inline size_t bitrev(size_t i, int log_n) {
    size_t r = 0;
    for (int b = 0; b < log_n; ++b) {
        if (i & (1ULL << b)) r |= (1ULL << (log_n - 1 - b));
    }
    return r;
}

inline int log2_size(size_t n) {
    int k = 0;
    while ((1ULL << k) < n) ++k;
    return k;
}

inline bool valid_n(size_t n) {
    return n == 64 || n == 128 || n == 256;
}

// Cooley-Tukey forward NTT (decimation in time), output in bit-reversed order.
// Uses zeta as a primitive (2n)-th root of unity.
inline void ntt_forward(int32_t* a, size_t n, int32_t q, int32_t zeta) {
    int log_n = log2_size(n);
    // Bit-reverse permutation.
    for (size_t i = 0; i < n; ++i) {
        size_t j = bitrev(i, log_n);
        if (j > i) {
            int32_t t = a[i]; a[i] = a[j]; a[j] = t;
        }
    }
    // Iterative butterflies.
    for (int s = 1; s <= log_n; ++s) {
        size_t m = 1ULL << s;
        size_t mh = m >> 1;
        // Principal m-th root: zeta is a (2n)-th root, so the m-th root is
        // zeta^((2n)/m).
        int32_t w_m = pow_q(zeta, (int32_t)((2 * n) / m), q);
        for (size_t k = 0; k < n; k += m) {
            int32_t w = 1;
            for (size_t j = 0; j < mh; ++j) {
                int32_t t = mul_q(w, a[k + j + mh], q);
                int32_t u = a[k + j];
                a[k + j]      = add_q(u, t, q);
                a[k + j + mh] = sub_q(u, t, q);
                w = mul_q(w, w_m, q);
            }
        }
    }
}

inline void ntt_inverse(int32_t* a, size_t n, int32_t q, int32_t zeta) {
    int32_t zeta_inv = inv_q(zeta, q);
    ntt_forward(a, n, q, zeta_inv);
    int32_t n_inv = inv_q((int32_t)n, q);
    for (size_t i = 0; i < n; ++i) a[i] = mul_q(a[i], n_inv, q);
}

// Schoolbook negacyclic multiplication: c[k] = sum a[i]*b[j], i+j == k mod n,
// with a sign flip when i+j >= n (since x^n = -1 mod x^n+1). O(n^2).
inline void schoolbook_negacyclic(const int32_t* a, const int32_t* b,
                                  int32_t* out, size_t n, int32_t q) {
    std::vector<int32_t> tmp(n, 0);
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            int32_t v = mul_q(a[i], b[j], q);
            size_t k = i + j;
            if (k < n) {
                tmp[k] = add_q(tmp[k], v, q);
            } else {
                tmp[k - n] = sub_q(tmp[k - n], v, q);
            }
        }
    }
    for (size_t i = 0; i < n; ++i) out[i] = tmp[i];
}

}  // namespace

// =============================================================================
// Kyber: q = 3329, primitive 256th root of unity in Z_q is 17.
// We support n in {64, 128, 256}; for n < 256 we use zeta^(256/n) as the
// primitive (2n)-th root with the same field.
// =============================================================================

extern "C" int gpukit_ntt_kyber_forward_cpu(int32_t* a, size_t n) {
    if (!valid_n(n)) return GPUKIT_ERR_BAD_SIZE;
    constexpr int32_t Q = 3329;
    // primitive 512th root: 17 satisfies 17^256 == -1 mod 3329, so it's a
    // primitive 512th root of unity (i.e. (2n)-th root for n=256). For other
    // n, we scale: if zeta_512 is the primitive 512th, then zeta_(2n) =
    // zeta_512^(512/(2n)) = zeta_512^(256/n).
    int32_t zeta_512 = 17;
    int32_t zeta = pow_q(zeta_512, (int32_t)(256 / n), Q);
    ntt_forward(a, n, Q, zeta);
    return GPUKIT_OK;
}

extern "C" int gpukit_ntt_kyber_inverse_cpu(int32_t* a, size_t n) {
    if (!valid_n(n)) return GPUKIT_ERR_BAD_SIZE;
    constexpr int32_t Q = 3329;
    int32_t zeta_512 = 17;
    int32_t zeta = pow_q(zeta_512, (int32_t)(256 / n), Q);
    ntt_inverse(a, n, Q, zeta);
    return GPUKIT_OK;
}

extern "C" int gpukit_ntt_kyber_negacyclic_mul_cpu(const int32_t* a, const int32_t* b,
                                                   int32_t* out, size_t n) {
    if (!valid_n(n)) return GPUKIT_ERR_BAD_SIZE;
    schoolbook_negacyclic(a, b, out, n, 3329);
    return GPUKIT_OK;
}

// =============================================================================
// Dilithium: q = 8380417 (= 2^23 - 2^13 + 1), primitive 512th root of unity is
// 1753. Same scaling as Kyber for n != 256.
// =============================================================================

extern "C" int gpukit_ntt_dilithium_forward_cpu(int32_t* a, size_t n) {
    if (!valid_n(n)) return GPUKIT_ERR_BAD_SIZE;
    constexpr int32_t Q = 8380417;
    int32_t zeta_512 = 1753;
    int32_t zeta = pow_q(zeta_512, (int32_t)(256 / n), Q);
    ntt_forward(a, n, Q, zeta);
    return GPUKIT_OK;
}

extern "C" int gpukit_ntt_dilithium_inverse_cpu(int32_t* a, size_t n) {
    if (!valid_n(n)) return GPUKIT_ERR_BAD_SIZE;
    constexpr int32_t Q = 8380417;
    int32_t zeta_512 = 1753;
    int32_t zeta = pow_q(zeta_512, (int32_t)(256 / n), Q);
    ntt_inverse(a, n, Q, zeta);
    return GPUKIT_OK;
}

extern "C" int gpukit_ntt_dilithium_negacyclic_mul_cpu(const int32_t* a, const int32_t* b,
                                                       int32_t* out, size_t n) {
    if (!valid_n(n)) return GPUKIT_ERR_BAD_SIZE;
    schoolbook_negacyclic(a, b, out, n, 8380417);
    return GPUKIT_OK;
}

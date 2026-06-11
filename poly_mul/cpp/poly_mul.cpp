// Polynomial multiplication — host body over Z_Q[X]/(X^n + 1) with
// Q = 998244353. Mirrors the Go reference at github.com/kinet-labs/crypto/polymul
// (MulNegacyclic schoolbook). NTT path uses ntt::forward/inverse with a
// psi=2n-th-root pre/post multiply (negacyclic via X^n = -1).
//
// Domain: STANDARD form throughout the public API. Inputs in [0, 2^64) are
// reduced mod Q on entry; outputs are in [0, Q).
//
// Algorithms:
//   * Schoolbook  O(n^2)    — always correct, fastest below n = 64
//   * NTT-based   O(n log n)— negacyclic via psi = 2n-th-root pre/post mul
//
// Crossover: schoolbook wins below n = 64. Matches Go reference dispatcher.

#include "poly_mul.hpp"
#include "ntt.hpp"

#include <cstdint>
#include <vector>

namespace kinet::crypto::poly_mul {

namespace {

inline uint64_t add_mod(uint64_t a, uint64_t b) {
    uint64_t s = a + b;
    if (s >= Q) s -= Q;
    return s;
}

inline uint64_t sub_mod(uint64_t a, uint64_t b) {
    return (a >= b) ? (a - b) : (a + Q - b);
}

inline uint64_t mul_mod(uint64_t a, uint64_t b) {
    // Q < 2^30 so a*b < 2^60 fits in uint64_t.
    return (a * b) % Q;
}

inline bool is_pow2(uint32_t n) {
    return n != 0 && (n & (n - 1)) == 0;
}

}  // namespace

bool multiply_schoolbook(uint64_t* result,
                         const uint64_t* a, uint32_t n,
                         const uint64_t* b) {
    if (result == nullptr || a == nullptr || b == nullptr || n == 0) {
        return false;
    }
    std::vector<uint64_t> ar(n), br(n);
    for (uint32_t i = 0; i < n; ++i) {
        ar[i] = a[i] % Q;
        br[i] = b[i] % Q;
        result[i] = 0;
    }
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            uint64_t prod = mul_mod(ar[i], br[j]);
            uint32_t k = i + j;
            if (k < n) {
                result[k] = add_mod(result[k], prod);
            } else {
                result[k - n] = sub_mod(result[k - n], prod);
            }
        }
    }
    return true;
}

bool multiply_ntt(uint64_t* result,
                  const uint64_t* a, uint32_t n,
                  const uint64_t* b) {
    if (result == nullptr || a == nullptr || b == nullptr) return false;
    if (!is_pow2(n)) return false;
    if (n < 2) return false;
    if (n > (1u << (kinet::crypto::ntt::MAX_LOG_N - 1))) return false;

    uint32_t log_n = 0;
    while ((1u << log_n) < n) ++log_n;
    uint64_t psi_exp = 1ULL << (kinet::crypto::ntt::MAX_LOG_N - (log_n + 1));
    uint64_t psi     = kinet::crypto::ntt::pow_mod(
                          kinet::crypto::ntt::PRIMITIVE_ROOT, psi_exp,
                          kinet::crypto::ntt::Q);
    uint64_t psi_inv = kinet::crypto::ntt::pow_mod(psi, Q - 2, Q);

    std::vector<uint64_t> aw(n), bw(n);
    {
        uint64_t pp = 1;
        for (uint32_t i = 0; i < n; ++i) {
            aw[i] = mul_mod(a[i] % Q, pp);
            bw[i] = mul_mod(b[i] % Q, pp);
            pp = mul_mod(pp, psi);
        }
    }

    auto ctx = kinet::crypto::ntt::make_context(n);
    kinet::crypto::ntt::forward(aw.data(), n, ctx);
    kinet::crypto::ntt::forward(bw.data(), n, ctx);

    std::vector<uint64_t> c(n);
    for (uint32_t i = 0; i < n; ++i) {
        c[i] = mul_mod(aw[i], bw[i]);
    }

    kinet::crypto::ntt::inverse(c.data(), n, ctx);

    {
        uint64_t pp_inv = 1;
        for (uint32_t i = 0; i < n; ++i) {
            result[i] = mul_mod(c[i], pp_inv);
            pp_inv = mul_mod(pp_inv, psi_inv);
        }
    }
    return true;
}

bool multiply(uint64_t* result,
              const uint64_t* a, uint32_t na,
              const uint64_t* b, uint32_t nb) {
    if (result == nullptr || a == nullptr || b == nullptr) return false;
    if (na == 0 || na != nb) return false;
    if (na < SCHOOLBOOK_THRESHOLD || !is_pow2(na)) {
        return multiply_schoolbook(result, a, na, b);
    }
    if (na > (1u << (kinet::crypto::ntt::MAX_LOG_N - 1))) {
        return multiply_schoolbook(result, a, na, b);
    }
    return multiply_ntt(result, a, na, b);
}

}  // namespace kinet::crypto::poly_mul

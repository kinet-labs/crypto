// Six-step NTT host body. See ntt_large.hpp for algorithm + contract.
//
// CPU layout: in-place, no transpose. Output is in "column-major bit-reversed"
// natural matrix layout where Y[k_col * N2 + k_row] is the (k_col, k_row)
// element of the 2-D NTT.
//
//   Forward:
//     1. For each j in [0, N2): radix-2 NTT of size N1 on column j (stride N2).
//     2. For each (i, j): a[i*N2 + j] *= omega_n^(i * j) where omega_n is
//        the primitive N-th root of unity.
//     3. For each i in [0, N1): radix-2 NTT of size N2 on row i (stride 1).
//
//   Inverse: undo step 3, step 2 (with omega_n^-1), step 1, then * 1/N.
//
// Hot-loop strategy:
//   q != 0: __uint128_t multiply, % q at the bottleneck.
//   q == 0: machine-word arithmetic; "% q" is a no-op (truncation).

#include "ntt_large.hpp"

#include <bit>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace kinet::crypto::ntt::large {

namespace {

inline uint64_t add_mod_q(uint64_t a, uint64_t b, uint64_t q) {
    if (q == 0) return a + b;                   // mod 2^64
    uint64_t s = a + b;
    if (s >= q || s < a) s -= q;
    return s;
}

inline uint64_t sub_mod_q(uint64_t a, uint64_t b, uint64_t q) {
    if (q == 0) return a - b;                   // mod 2^64
    return (a >= b) ? (a - b) : (a + q - b);
}

inline uint64_t mul_mod_q(uint64_t a, uint64_t b, uint64_t q) {
    if (q == 0) return a * b;                   // mod 2^64
    __uint128_t t = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b);
    return static_cast<uint64_t>(t % q);
}

inline uint64_t pow_mod_q(uint64_t base, uint64_t exp, uint64_t q) {
    uint64_t r = 1;
    uint64_t b = (q == 0) ? base : (base % q);
    while (exp > 0) {
        if (exp & 1u) r = mul_mod_q(r, b, q);
        b = mul_mod_q(b, b, q);
        exp >>= 1;
    }
    return r;
}

// Modular inverse. q prime: Fermat. q==0: Hensel-lifted Newton iteration in
// (Z/2^64Z)* (well-defined for odd a only).
uint64_t inv_mod_q(uint64_t a, uint64_t q) {
    if (q != 0) return pow_mod_q(a, q - 2, q);
    if ((a & 1u) == 0) {
        throw std::invalid_argument("ntt_large: inverse mod 2^64 requires odd a");
    }
    uint64_t x = 1;
    for (int i = 0; i < 6; ++i) x = x * (2u - a * x);
    return x;
}

inline uint32_t reverse_bits(uint32_t x, uint32_t log_n) {
    x = ((x >> 1) & 0x55555555u) | ((x & 0x55555555u) << 1);
    x = ((x >> 2) & 0x33333333u) | ((x & 0x33333333u) << 2);
    x = ((x >> 4) & 0x0F0F0F0Fu) | ((x & 0x0F0F0F0Fu) << 4);
    x = ((x >> 8) & 0x00FF00FFu) | ((x & 0x00FF00FFu) << 8);
    x = (x >> 16) | (x << 16);
    return x >> (32 - log_n);
}

inline void bit_reverse_strided(uint64_t* a, uint32_t n, uint32_t log_n,
                                uint32_t stride) {
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t j = reverse_bits(i, log_n);
        if (i < j) {
            uint64_t t = a[i * stride];
            a[i * stride] = a[j * stride];
            a[j * stride] = t;
        }
    }
}

// In-place radix-2 Cooley-Tukey NTT on a strided sub-array. `tw[s-1]` is the
// s-th-stage step root, where the underlying primitive root is `omega_sub`.
// Caller pre-builds tw via build_step_roots().
void sub_ntt(uint64_t* a, uint32_t n, uint32_t log_n, uint32_t stride,
             const uint64_t* tw, uint64_t q) {
    bit_reverse_strided(a, n, log_n, stride);
    for (uint32_t s = 1; s <= log_n; ++s) {
        uint32_t m    = 1u << s;
        uint32_t half = m >> 1;
        uint64_t wm   = tw[s - 1];
        for (uint32_t k = 0; k < n; k += m) {
            uint64_t w = 1;
            for (uint32_t j = 0; j < half; ++j) {
                size_t lo = static_cast<size_t>(k + j) * stride;
                size_t hi = lo + static_cast<size_t>(half) * stride;
                uint64_t u = a[lo];
                uint64_t t = mul_mod_q(w, a[hi], q);
                a[lo] = add_mod_q(u, t, q);
                a[hi] = sub_mod_q(u, t, q);
                w = mul_mod_q(w, wm, q);
            }
        }
    }
}

// Build step-root table for an N=2^log_n radix-2 NTT, given a primitive
// N-th root of unity `omega_n` modulo q. tw[s-1] = omega_n^(N/2^s).
std::vector<uint64_t> build_step_roots(uint32_t log_n,
                                       uint64_t omega_n,
                                       uint64_t q) {
    std::vector<uint64_t> tw(log_n);
    uint64_t n = 1ULL << log_n;
    for (uint32_t s = 1; s <= log_n; ++s) {
        uint64_t exp = n >> s;     // n / 2^s
        tw[s - 1] = pow_mod_q(omega_n, exp, q);
    }
    return tw;
}

}  // namespace

// =============================================================================
// Public API
// =============================================================================

void pick_factors(uint32_t n, uint32_t& n1, uint32_t& n2) {
    uint32_t log_n = static_cast<uint32_t>(std::countr_zero(n));
    uint32_t log_n1 = log_n / 2;
    uint32_t log_n2 = log_n - log_n1;
    n1 = 1u << log_n1;
    n2 = 1u << log_n2;
}

LargeContext make_context(uint32_t n, uint64_t q, uint64_t omega) {
    if (n == 0 || (n & (n - 1)) != 0) {
        throw std::invalid_argument("ntt_large::make_context: N must be power of two");
    }
    uint32_t log_n = static_cast<uint32_t>(std::countr_zero(n));
    if (log_n > MAX_LOG_N) {
        throw std::invalid_argument("ntt_large::make_context: N exceeds 2^MAX_LOG_N");
    }

    LargeContext ctx;
    ctx.n     = n;
    ctx.q     = q;
    ctx.omega = omega;
    pick_factors(n, ctx.n1, ctx.n2);
    ctx.log_n1 = static_cast<uint32_t>(std::countr_zero(ctx.n1));
    ctx.log_n2 = static_cast<uint32_t>(std::countr_zero(ctx.n2));

    // omega is a 2N-th primitive root; the N-th root we transform with is
    // omega^2. Each sub-NTT uses its own primitive root:
    //   omega_N1 = omega_N^(N/N1) = omega_N^N2
    //   omega_N2 = omega_N^(N/N2) = omega_N^N1
    uint64_t omega_n     = mul_mod_q(omega, omega, q);
    uint64_t omega_n_inv = inv_mod_q(omega_n, q);
    uint64_t omega_n1     = pow_mod_q(omega_n,     static_cast<uint64_t>(ctx.n2), q);
    uint64_t omega_n1_inv = pow_mod_q(omega_n_inv, static_cast<uint64_t>(ctx.n2), q);
    uint64_t omega_n2     = pow_mod_q(omega_n,     static_cast<uint64_t>(ctx.n1), q);
    uint64_t omega_n2_inv = pow_mod_q(omega_n_inv, static_cast<uint64_t>(ctx.n1), q);

    ctx.tw_col_fwd = build_step_roots(ctx.log_n1, omega_n1,     q);
    ctx.tw_col_inv = build_step_roots(ctx.log_n1, omega_n1_inv, q);
    ctx.tw_row_fwd = build_step_roots(ctx.log_n2, omega_n2,     q);
    ctx.tw_row_inv = build_step_roots(ctx.log_n2, omega_n2_inv, q);

    // Diagonal twiddles: omega_n^(i*j).
    ctx.diag_fwd.resize(static_cast<size_t>(n));
    ctx.diag_inv.resize(static_cast<size_t>(n));
    for (uint32_t i = 0; i < ctx.n1; ++i) {
        uint64_t base_fwd = pow_mod_q(omega_n,     static_cast<uint64_t>(i), q);
        uint64_t base_inv = pow_mod_q(omega_n_inv, static_cast<uint64_t>(i), q);
        uint64_t cur_fwd = 1, cur_inv = 1;
        size_t row = static_cast<size_t>(i) * ctx.n2;
        for (uint32_t j = 0; j < ctx.n2; ++j) {
            ctx.diag_fwd[row + j] = cur_fwd;
            ctx.diag_inv[row + j] = cur_inv;
            cur_fwd = mul_mod_q(cur_fwd, base_fwd, q);
            cur_inv = mul_mod_q(cur_inv, base_inv, q);
        }
    }

    ctx.n_inv = inv_mod_q(static_cast<uint64_t>(n), q);
    return ctx;
}

void forward(uint64_t* a, const LargeContext& ctx) {
    if (ctx.n <= 1) return;
    const uint64_t q = ctx.q;
    const uint32_t N1 = ctx.n1, N2 = ctx.n2;

    // Step 1: column NTTs of size N1, stride N2.
    for (uint32_t j = 0; j < N2; ++j) {
        sub_ntt(a + j, N1, ctx.log_n1, /*stride=*/N2,
                ctx.tw_col_fwd.data(), q);
    }
    // Step 2: diagonal twiddle multiply.
    for (uint32_t i = 0; i < N1; ++i) {
        size_t row = static_cast<size_t>(i) * N2;
        for (uint32_t j = 0; j < N2; ++j) {
            a[row + j] = mul_mod_q(a[row + j], ctx.diag_fwd[row + j], q);
        }
    }
    // Step 3: row NTTs of size N2, stride 1.
    for (uint32_t i = 0; i < N1; ++i) {
        sub_ntt(a + static_cast<size_t>(i) * N2, N2, ctx.log_n2, /*stride=*/1,
                ctx.tw_row_fwd.data(), q);
    }
}

void inverse(uint64_t* a, const LargeContext& ctx) {
    if (ctx.n <= 1) return;
    const uint64_t q = ctx.q;
    const uint32_t N1 = ctx.n1, N2 = ctx.n2;

    // Reverse step 3: inverse row NTTs of size N2, stride 1.
    for (uint32_t i = 0; i < N1; ++i) {
        sub_ntt(a + static_cast<size_t>(i) * N2, N2, ctx.log_n2, /*stride=*/1,
                ctx.tw_row_inv.data(), q);
    }
    // Reverse step 2: inverse diagonal twiddle multiply.
    for (uint32_t i = 0; i < N1; ++i) {
        size_t row = static_cast<size_t>(i) * N2;
        for (uint32_t j = 0; j < N2; ++j) {
            a[row + j] = mul_mod_q(a[row + j], ctx.diag_inv[row + j], q);
        }
    }
    // Reverse step 1: inverse column NTTs.
    for (uint32_t j = 0; j < N2; ++j) {
        sub_ntt(a + j, N1, ctx.log_n1, /*stride=*/N2,
                ctx.tw_col_inv.data(), q);
    }
    // 1/N final scaling.
    for (size_t k = 0; k < ctx.n; ++k) {
        a[k] = mul_mod_q(a[k], ctx.n_inv, q);
    }
}

}  // namespace kinet::crypto::ntt::large

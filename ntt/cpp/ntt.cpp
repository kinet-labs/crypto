// Number-Theoretic Transform — host body.
//
// Mirrors the Go reference at github.com/kinet-labs/crypto/ntt (NTT / INTT) for
// the generic-prime path, and pins the Cyclone-FFT prime Q = 998244353 with
// PRIMITIVE_ROOT = 629671588 for the optimized Montgomery path. Per-coef
// byte output is identical to the Go reference for any input on the generic
// path; the JSON KAT vectors lock the Cyclone path coefficient-by-coefficient.
//
// =============================================================================
// DOMAIN CONVENTIONS
// =============================================================================
//
//   STANDARD     — values in [0, Q). What you usually mean by "x mod Q".
//   MONTGOMERY   — REDC-domain encoding x_mont = x * R mod Q with R = 2^32.
//
// Public API (`kinet::crypto::ntt::` namespace):
//   * Inputs  : STANDARD form, in [0, 2^64), reduced mod Q on entry.
//   * Outputs : STANDARD form, guaranteed in [0, Q).
//
// Internal hot loop:
//   * `a[]` STANDARD throughout the butterfly.
//   * Twiddles in `Context::tw_fwd` / `tw_inv` are MONTGOMERY.
//   * mont_mul(a_std, w_mont) returns standard form.

#include "ntt.hpp"

#include <bit>
#include <cstdint>
#include <stdexcept>

namespace kinet::crypto::ntt {

namespace {

inline uint64_t add_mod(uint64_t a, uint64_t b, uint64_t q) {
    uint64_t s = a + b;
    if (s >= q) s -= q;
    return s;
}

inline uint64_t sub_mod(uint64_t a, uint64_t b, uint64_t q) {
    return (a >= b) ? (a - b) : (a + q - b);
}

inline uint64_t mul_mod_full(uint64_t a, uint64_t b, uint64_t q) {
    __uint128_t t = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b);
    return static_cast<uint64_t>(t % q);
}

inline uint64_t mont_redc(uint64_t t) {
    uint64_t m = (t & MONT_R_MASK) * MONT_Q_INV32;
    m &= MONT_R_MASK;
    uint64_t u = (t + m * Q) >> MONT_R_BITS;
    if (u >= Q) u -= Q;
    return u;
}

inline uint64_t mont_mul(uint64_t a, uint64_t b_mont) {
    return mont_redc(a * b_mont);
}

inline uint64_t to_mont(uint64_t a) {
    return mont_redc(a * MONT_R2_MOD_Q);
}

inline uint32_t reverse_bits(uint32_t x, uint32_t log_n) {
    x = ((x >> 1) & 0x55555555u) | ((x & 0x55555555u) << 1);
    x = ((x >> 2) & 0x33333333u) | ((x & 0x33333333u) << 2);
    x = ((x >> 4) & 0x0F0F0F0Fu) | ((x & 0x0F0F0F0Fu) << 4);
    x = ((x >> 8) & 0x00FF00FFu) | ((x & 0x00FF00FFu) << 8);
    x = (x >> 16) | (x << 16);
    return x >> (32 - log_n);
}

inline void bit_reverse_in_place(uint64_t* a, uint32_t n, uint32_t log_n) {
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t j = reverse_bits(i, log_n);
        if (i < j) {
            uint64_t t = a[i]; a[i] = a[j]; a[j] = t;
        }
    }
}

}  // namespace

uint64_t pow_mod(uint64_t base, uint64_t exp, uint64_t q) {
    uint64_t r = 1;
    uint64_t b = base % q;
    while (exp > 0) {
        if (exp & 1u) r = mul_mod_full(r, b, q);
        b = mul_mod_full(b, b, q);
        exp >>= 1;
    }
    return r;
}

Context make_context(uint32_t n) {
    if (n == 0 || (n & (n - 1)) != 0) {
        throw std::invalid_argument("ntt::make_context: n must be a power of two");
    }
    if (n > (1u << MAX_LOG_N)) {
        throw std::invalid_argument("ntt::make_context: n exceeds 2^MAX_LOG_N");
    }

    Context ctx;
    ctx.n     = n;
    ctx.log_n = static_cast<uint32_t>(std::countr_zero(n));

    ctx.tw_fwd.resize(ctx.log_n);
    ctx.tw_inv.resize(ctx.log_n);

    for (uint32_t s = 1; s <= ctx.log_n; ++s) {
        uint64_t exp_fwd  = 1ULL << (MAX_LOG_N - s);
        uint64_t wm_fwd   = pow_mod(PRIMITIVE_ROOT, exp_fwd, Q);
        uint64_t wm_inv   = pow_mod(wm_fwd, Q - 2, Q);
        ctx.tw_fwd[s - 1] = to_mont(wm_fwd);
        ctx.tw_inv[s - 1] = to_mont(wm_inv);
    }

    uint64_t inv_n = pow_mod(static_cast<uint64_t>(n), Q - 2, Q);
    ctx.inv_n_mont = to_mont(inv_n);

    return ctx;
}

namespace {

inline void butterfly(uint64_t* a,
                      uint32_t n, uint32_t log_n,
                      const uint64_t* tw_mont) {
    bit_reverse_in_place(a, n, log_n);

    constexpr uint64_t MONT_ONE = MONT_R_MOD_Q;

    for (uint32_t s = 1; s <= log_n; ++s) {
        uint32_t m    = 1u << s;
        uint32_t half = m >> 1;
        uint64_t wm   = tw_mont[s - 1];
        for (uint32_t k = 0; k < n; k += m) {
            uint64_t w = MONT_ONE;
            for (uint32_t j = 0; j < half; ++j) {
                uint64_t u = a[k + j];
                uint64_t t = mont_mul(a[k + j + half], w);
                a[k + j]            = add_mod(u, t, Q);
                a[k + j + half]     = sub_mod(u, t, Q);
                w = mont_redc(w * wm);
            }
        }
    }
}

}  // namespace

void forward(uint64_t* a, uint32_t n, const Context& ctx) {
    if (n != ctx.n) {
        throw std::invalid_argument("ntt::forward: n != ctx.n");
    }
    if (n <= 1) return;
    butterfly(a, n, ctx.log_n, ctx.tw_fwd.data());
}

void inverse(uint64_t* a, uint32_t n, const Context& ctx) {
    if (n != ctx.n) {
        throw std::invalid_argument("ntt::inverse: n != ctx.n");
    }
    if (n == 0) return;
    if (n == 1) return;
    butterfly(a, n, ctx.log_n, ctx.tw_inv.data());
    for (uint32_t i = 0; i < n; ++i) {
        a[i] = mont_mul(a[i], ctx.inv_n_mont);
    }
}

namespace {

bool ntt_generic(uint64_t* a, uint32_t n, uint64_t q, uint64_t omega) {
    if (n == 0 || (n & (n - 1)) != 0 || q == 0) return false;
    if (n == 1) return true;
    uint32_t log_n = static_cast<uint32_t>(std::countr_zero(n));
    bit_reverse_in_place(a, n, log_n);
    for (uint32_t s = 1; s <= log_n; ++s) {
        uint32_t m    = 1u << s;
        uint32_t half = m >> 1;
        uint64_t wm   = pow_mod(omega, static_cast<uint64_t>(n / m), q);
        for (uint32_t k = 0; k < n; k += m) {
            uint64_t w = 1;
            for (uint32_t j = 0; j < half; ++j) {
                uint64_t u = a[k + j] % q;
                uint64_t t = mul_mod_full(w, a[k + j + half] % q, q);
                a[k + j]        = add_mod(u, t, q);
                a[k + j + half] = sub_mod(u, t, q);
                w = mul_mod_full(w, wm, q);
            }
        }
    }
    return true;
}

}  // namespace

bool forward_generic(uint64_t* a, uint32_t n, uint64_t q, uint64_t omega) {
    return ntt_generic(a, n, q, omega);
}

bool inverse_generic(uint64_t* a, uint32_t n, uint64_t q, uint64_t omega_inv) {
    if (!ntt_generic(a, n, q, omega_inv)) return false;
    if (n <= 1) return true;
    uint64_t n_inv = pow_mod(static_cast<uint64_t>(n), q - 2, q);
    for (uint32_t i = 0; i < n; ++i) {
        a[i] = mul_mod_full(a[i], n_inv, q);
    }
    return true;
}

}  // namespace kinet::crypto::ntt

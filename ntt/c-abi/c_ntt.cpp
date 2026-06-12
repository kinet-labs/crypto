// NTT C-ABI shim — extern "C" entry points only. Body lives in cpp/ntt.cpp
// (small N, Cyclone-FFT prime path) and cpp/ntt_large.cpp (N > 2^16, generic
// q including q = 2^64 for TFHE).
//
// Dispatch:
//   N <= 2^16, modulus = Cyclone Q          -> ntt::forward / ntt::inverse
//   N <= 2^16, modulus != Cyclone Q         -> ntt::forward_generic / ::inverse_generic
//   N >  2^16, modulus prime                -> ntt::large::forward / ::inverse
//   N >  2^16, modulus = 2^64 (TFHE)        -> ntt::large::forward / ::inverse with q=0 sentinel
//
// `root_inv` is the modular inverse of `root` mod `modulus`. For ntt_inverse
// we accept either the original root (and invert internally) or the
// caller-supplied inverse, mirroring the Go reference's API.

#include "crypto.h"
#include "ntt.hpp"
#include "ntt_large.hpp"

#include <cstdint>
#include <stdexcept>
#include <unordered_map>

namespace {

const kinet::crypto::ntt::Context& cyclone_context(uint32_t n) {
    static thread_local std::unordered_map<uint32_t, kinet::crypto::ntt::Context> cache;
    auto it = cache.find(n);
    if (it == cache.end()) {
        it = cache.emplace(n, kinet::crypto::ntt::make_context(n)).first;
    }
    return it->second;
}

inline bool is_pow2_size(size_t n) {
    return n != 0 && (n & (n - 1)) == 0;
}

inline bool is_cyclone(uint64_t modulus, uint64_t root) {
    return modulus == kinet::crypto::ntt::Q
        && root    == kinet::crypto::ntt::PRIMITIVE_ROOT;
}

// Cache the LargeContext per (N, modulus, root) tuple so repeated calls don't
// rebuild diagonal-twiddle tables. Key packs all three into a 192-bit value
// modeled as a string, but a struct + custom hash is simpler and faster.
struct LargeKey {
    uint32_t n;
    uint64_t q;
    uint64_t omega;
    bool operator==(const LargeKey& o) const {
        return n == o.n && q == o.q && omega == o.omega;
    }
};
struct LargeKeyHash {
    size_t operator()(const LargeKey& k) const noexcept {
        // FNV-ish mix over the three fields. Collisions are harmless: equality
        // is checked separately.
        uint64_t h = static_cast<uint64_t>(k.n) * 0x9E3779B97F4A7C15ULL;
        h ^= k.q + 0x9E3779B97F4A7C15ULL + (h << 6) + (h >> 2);
        h ^= k.omega + 0x9E3779B97F4A7C15ULL + (h << 6) + (h >> 2);
        return static_cast<size_t>(h);
    }
};

const kinet::crypto::ntt::large::LargeContext&
large_context(uint32_t n, uint64_t modulus, uint64_t root) {
    static thread_local std::unordered_map<
        LargeKey, kinet::crypto::ntt::large::LargeContext, LargeKeyHash> cache;
    LargeKey k{n, modulus, root};
    auto it = cache.find(k);
    if (it == cache.end()) {
        it = cache.emplace(
            k,
            kinet::crypto::ntt::large::make_context(n, modulus, root)).first;
    }
    return it->second;
}

}  // namespace

extern "C" int ntt_forward(uint64_t* coeffs, size_t n,
                           uint64_t modulus, uint64_t root) {
    if (coeffs == nullptr || !is_pow2_size(n)) {
        return CRYPTO_ERR_INPUT;
    }
    // Small-N (<= 2^16) path: existing radix-2 implementation.
    if (n <= (1u << kinet::crypto::ntt::MAX_LOG_N)) {
        if (modulus == 0) return CRYPTO_ERR_INPUT;
        if (is_cyclone(modulus, root)) {
            const auto& ctx = cyclone_context(static_cast<uint32_t>(n));
            kinet::crypto::ntt::forward(coeffs, static_cast<uint32_t>(n), ctx);
            return CRYPTO_OK;
        }
        if (!kinet::crypto::ntt::forward_generic(coeffs, static_cast<uint32_t>(n),
                                                modulus, root)) {
            return CRYPTO_ERR_INPUT;
        }
        return CRYPTO_OK;
    }
    // Large-N (> 2^16) path: six-step.
    if (n > (1u << kinet::crypto::ntt::large::MAX_LOG_N)) {
        return CRYPTO_ERR_INPUT;
    }
    try {
        const auto& ctx = large_context(static_cast<uint32_t>(n), modulus, root);
        kinet::crypto::ntt::large::forward(coeffs, ctx);
    } catch (const std::invalid_argument&) {
        return CRYPTO_ERR_INPUT;
    }
    return CRYPTO_OK;
}

extern "C" int ntt_inverse(uint64_t* coeffs, size_t n,
                           uint64_t modulus, uint64_t root_inv) {
    if (coeffs == nullptr || !is_pow2_size(n)) {
        return CRYPTO_ERR_INPUT;
    }
    if (n <= (1u << kinet::crypto::ntt::MAX_LOG_N)) {
        if (modulus == 0) return CRYPTO_ERR_INPUT;
        if (modulus == kinet::crypto::ntt::Q
            && (root_inv == kinet::crypto::ntt::PRIMITIVE_ROOT
                || root_inv == kinet::crypto::ntt::pow_mod(
                                  kinet::crypto::ntt::PRIMITIVE_ROOT,
                                  kinet::crypto::ntt::Q - 2,
                                  kinet::crypto::ntt::Q))) {
            const auto& ctx = cyclone_context(static_cast<uint32_t>(n));
            kinet::crypto::ntt::inverse(coeffs, static_cast<uint32_t>(n), ctx);
            return CRYPTO_OK;
        }
        if (!kinet::crypto::ntt::inverse_generic(coeffs, static_cast<uint32_t>(n),
                                                modulus, root_inv)) {
            return CRYPTO_ERR_INPUT;
        }
        return CRYPTO_OK;
    }
    if (n > (1u << kinet::crypto::ntt::large::MAX_LOG_N)) {
        return CRYPTO_ERR_INPUT;
    }
    // For the large-N path the LargeContext caches by (N, modulus, root)
    // where root is the *forward* primitive 2N-th root. The caller passed
    // root_inv; reconstruct the forward root: omega = inverse_of(root_inv).
    // For prime modulus that's pow(root_inv, modulus-2, modulus); for q=2^64
    // we use Hensel-Newton inverse.
    try {
        // Reuse ntt_large's inv_mod_q via make_context indirection: the
        // simplest correct path is to ask LargeContext to derive both
        // directions at construction time. Rebuild the key from root_inv by
        // inverting it; re-using the same cache means forward+inverse on
        // the same (N, modulus, root) reuses one entry.
        uint64_t omega_fwd;
        if (modulus != 0) {
            // Fermat
            uint64_t r = 1, b = root_inv % modulus;
            uint64_t e = modulus - 2;
            while (e > 0) {
                if (e & 1u) {
                    __uint128_t t = static_cast<__uint128_t>(r) * b;
                    r = static_cast<uint64_t>(t % modulus);
                }
                __uint128_t t = static_cast<__uint128_t>(b) * b;
                b = static_cast<uint64_t>(t % modulus);
                e >>= 1;
            }
            omega_fwd = r;
        } else {
            // q = 0 means modulus = 2^64; Hensel-Newton inverse (root_inv must
            // be odd in (Z/2^64Z)*).
            if ((root_inv & 1u) == 0) return CRYPTO_ERR_INPUT;
            uint64_t x = 1;
            for (int i = 0; i < 6; ++i) x = x * (2u - root_inv * x);
            omega_fwd = x;
        }
        const auto& ctx = large_context(static_cast<uint32_t>(n), modulus, omega_fwd);
        kinet::crypto::ntt::large::inverse(coeffs, ctx);
    } catch (const std::invalid_argument&) {
        return CRYPTO_ERR_INPUT;
    }
    return CRYPTO_OK;
}

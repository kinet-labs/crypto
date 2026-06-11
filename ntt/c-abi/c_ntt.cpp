// NTT C-ABI shim — extern "C" entry points only. Body lives in cpp/ntt.cpp.

#include "kinet_crypto.h"
#include "ntt.hpp"

#include <cstdint>
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

}  // namespace

extern "C" int ntt_forward(uint64_t* coeffs, size_t n,
                           uint64_t modulus, uint64_t root) {
    if (coeffs == nullptr || !is_pow2_size(n) || modulus == 0) {
        return CRYPTO_ERR_INPUT;
    }
    if (n > (1u << kinet::crypto::ntt::MAX_LOG_N)) {
        return CRYPTO_ERR_INPUT;
    }
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

extern "C" int ntt_inverse(uint64_t* coeffs, size_t n,
                           uint64_t modulus, uint64_t root_inv) {
    if (coeffs == nullptr || !is_pow2_size(n) || modulus == 0) {
        return CRYPTO_ERR_INPUT;
    }
    if (n > (1u << kinet::crypto::ntt::MAX_LOG_N)) {
        return CRYPTO_ERR_INPUT;
    }
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

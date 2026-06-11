// poly_mul C-ABI shim — extern "C" entry points only. Body in cpp/poly_mul.cpp.
//
// Currently supports exactly the Cyclone-FFT prime (Q, PRIMITIVE_ROOT). Any
// other (modulus, root) pair returns CRYPTO_ERR_INPUT — the surface for
// arbitrary primes is the generic NTT path (ntt_forward / ntt_inverse), not
// poly_mul (which encodes a specific negacyclic ring).

#include "kinet_crypto.h"
#include "ntt.hpp"
#include "poly_mul.hpp"

#include <cstdint>

namespace {

inline bool is_cyclone(uint64_t modulus, uint64_t root) {
    return modulus == kinet::crypto::ntt::Q
        && root    == kinet::crypto::ntt::PRIMITIVE_ROOT;
}

}  // namespace

extern "C" int poly_mul(const uint64_t* a,
                        const uint64_t* b,
                        size_t          n,
                        uint64_t        modulus,
                        uint64_t        root,
                        uint64_t*       out) {
    if (a == nullptr || b == nullptr || out == nullptr) {
        return CRYPTO_ERR_INPUT;
    }
    if (n == 0) {
        return CRYPTO_ERR_INPUT;
    }
    if (n > static_cast<size_t>(UINT32_MAX)) {
        return CRYPTO_ERR_INPUT;
    }
    if (!is_cyclone(modulus, root)) {
        return CRYPTO_ERR_INPUT;
    }
    bool ok = kinet::crypto::poly_mul::multiply(out,
                                              a, static_cast<uint32_t>(n),
                                              b, static_cast<uint32_t>(n));
    return ok ? CRYPTO_OK : CRYPTO_ERR_INPUT;
}

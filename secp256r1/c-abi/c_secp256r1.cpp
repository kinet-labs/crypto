// =============================================================================
// secp256r1 - C ABI implementation
// =============================================================================
//
// Wires secp256r1_verify to evmmax::secp256r1::verify (NIST P-256 ECDSA).
// SHA-256(msg) per EIP-7212 / EIP-7951 derives the 32-byte digest. Hashing is
// delegated to the in-tree first-party cevm::crypto::sha256 body so this TU
// has no OpenSSL dependency.
//
// Pubkey encoding:    64 bytes = qx (32 BE) || qy (32 BE).
// Signature encoding: 64 bytes = r  (32 BE) || s  (32 BE).
//
// Returns CRYPTO_OK on valid signature, CRYPTO_ERR_VERIFY on invalid signature,
// CRYPTO_ERR_INPUT on malformed input.

#include "crypto.h"

#include "../cpp/secp256r1.hpp"
#include "sha256.hpp"  // cevm::crypto::sha256

#include <cstddef>
#include <cstdint>

namespace {
intx::uint256 be_to_u256(const uint8_t b[32]) noexcept {
    intx::uint256 r{};
    for (int i = 0; i < 32; ++i) {
        r = (r << 8) | uint64_t{b[i]};
    }
    return r;
}
}  // namespace

extern "C" int secp256r1_verify(const uint8_t pk[64],
                                const uint8_t* msg, size_t msg_len,
                                const uint8_t sig[64]) {
    if (pk == nullptr || sig == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;

    // SHA-256(msg) per EIP-7212 / EIP-7951. Direct call into the in-tree
    // first-party body (cevm::crypto::sha256) — no OpenSSL, no C-ABI hop.
    ethash::hash256 h{};
    cevm::crypto::sha256(reinterpret_cast<std::byte*>(h.bytes),
                         reinterpret_cast<const std::byte*>(msg), msg_len);

    const auto qx = be_to_u256(pk);
    const auto qy = be_to_u256(pk + 32);
    const auto r  = be_to_u256(sig);
    const auto s  = be_to_u256(sig + 32);

    const bool ok = evmmax::secp256r1::verify(h, r, s, qx, qy);
    return ok ? CRYPTO_OK : CRYPTO_ERR_VERIFY;
}

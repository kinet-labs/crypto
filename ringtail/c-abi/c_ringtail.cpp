// =============================================================================
// kinet-labs/crypto/ringtail - C ABI shim
// =============================================================================
//
// Thin extern "C" surface over the C++ body in ringtail/cpp/ringtail.{hpp,cpp}.
// The opaque ringtail_ctx forward-declared in <crypto.h> aliases the C++
// kinet::crypto::ringtail::Context struct via reinterpret_cast on the boundary.
//
// =============================================================================

#include "crypto.h"
#include "../cpp/ringtail.hpp"

namespace rt = kinet::crypto::ringtail;

// The opaque struct in <crypto.h> is `ringtail_ctx`; we tunnel through to the
// C++ Context. Layout-compatibility is not required because the boundary is
// pointer-only.
struct ringtail_ctx {
    rt::Context cpp;
};

extern "C" int ringtail_setup(uint32_t t, uint32_t n, ringtail_ctx** out) {
    if (out == nullptr) return CRYPTO_ERR_INPUT;
    rt::Context* cpp_ctx = nullptr;
    int rc = rt::Setup(t, n, /*seed*/ nullptr, /*seed_len*/ 0, &cpp_ctx);
    if (rc != CRYPTO_OK) return rc;
    auto* shell = new ringtail_ctx{std::move(*cpp_ctx)};
    delete cpp_ctx;
    *out = shell;
    return CRYPTO_OK;
}

extern "C" int ringtail_sign(ringtail_ctx* ctx,
                             const uint8_t* msg, size_t msg_len,
                             uint8_t* sig, size_t* sig_len) {
    if (ctx == nullptr || sig_len == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    return rt::Sign(&ctx->cpp, msg, msg_len, sig, sig_len);
}

extern "C" int ringtail_verify(const uint8_t* pk, size_t pk_len,
                               const uint8_t* msg, size_t msg_len,
                               const uint8_t* sig, size_t sig_len) {
    if (pk_len  > 0 && pk  == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    if (sig_len > 0 && sig == nullptr) return CRYPTO_ERR_INPUT;
    return rt::Verify(pk, pk_len, msg, msg_len, sig, sig_len);
}

extern "C" int ringtail_pk(const ringtail_ctx* ctx, uint8_t* out_pk, size_t out_len) {
    if (ctx == nullptr || out_pk == nullptr) return CRYPTO_ERR_INPUT;
    if (out_len < rt::PK_BYTES) return CRYPTO_ERR_LENGTH;
    return rt::SerializePK(&ctx->cpp, out_pk);
}

extern "C" size_t ringtail_pk_size(void) {
    return rt::PK_BYTES;
}

extern "C" size_t ringtail_sig_size(void) {
    return rt::SIG_BYTES;
}

extern "C" void ringtail_destroy(ringtail_ctx* ctx) {
    delete ctx;
}

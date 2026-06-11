// Custom SHA-512 hook for ed25519-donna. Activated by ED25519_CUSTOMHASH.
//
// Forwards to kinet::crypto::ed25519::detail::sha512* in sha512_minimal.hpp.
// Header lives in kinet-labs/crypto/ed25519/cpp/, included from ed25519.cpp's
// translation unit, so the namespace is reachable.
//
// Resolved by the include-path ordering in ed25519/CMakeLists.txt: the
// kinet-labs/crypto/ed25519/cpp/ directory is added BEFORE the fetched
// kinet-labs/ed25519-donna source dir, so this kinet-modified shim wins over the
// upstream stub of the same name.

#ifndef ED25519_HASH_CUSTOM_H
#define ED25519_HASH_CUSTOM_H

#include "sha512_minimal.hpp"

typedef struct ed25519_hash_context {
    kinet::crypto::ed25519::detail::Sha512Ctx ctx;
} ed25519_hash_context;

static void ed25519_hash_init(ed25519_hash_context* ctx) {
    kinet::crypto::ed25519::detail::sha512_init(ctx->ctx);
}

static void ed25519_hash_update(ed25519_hash_context* ctx,
                                const uint8_t* in, size_t inlen) {
    kinet::crypto::ed25519::detail::sha512_update(ctx->ctx, in, inlen);
}

static void ed25519_hash_final(ed25519_hash_context* ctx, uint8_t* hash) {
    kinet::crypto::ed25519::detail::sha512_final(ctx->ctx, hash);
}

static void ed25519_hash(uint8_t* hash, const uint8_t* in, size_t inlen) {
    kinet::crypto::ed25519::detail::sha512(in, inlen, hash);
}

#endif

// Custom SHA-512 hook for ed25519-donna. Activated by ED25519_CUSTOMHASH.
//
// Forwards to kinet::crypto::ed25519::detail::sha512* in sha512_minimal.hpp.
// Header lives in kinet-labs/crypto/ed25519/cpp/, included from ed25519.cpp's
// translation unit, so the namespace is reachable.

#ifndef ED25519_HASH_CUSTOM_H
#define ED25519_HASH_CUSTOM_H

#include "../sha512_minimal.hpp"

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

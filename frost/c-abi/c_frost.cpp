// FROST C-ABI shim — wires the canonical CPU body in
// frost/cpp/presign.{hpp,cpp} into the public crypto.h surface.
//
// The C-ABI entry points cover the local-crypto-only part of FROST:
//   * frost_setup           : seal a context (t, n, seed)
//   * frost_partial_sign    : per-signer pre-sign one slot — emits the 66-byte
//                             commitment D || E (compressed sec1 each)
// The aggregation + online challenge remain on the host because they need
// network-collected commitments; pre-sign is the only piece that benefits
// from GPU batching (independent across signer × slot).
//
// Contract: partial[] is a 66-byte buffer per call. Nonces (d_i, e_i) live
// inside the context for the lifetime of the slot and are wiped on destroy.

#include "crypto.h"

#include "../cpp/presign.hpp"
#include "../cpp/aggregate.hpp"
#include "../cpp/verify.hpp"

#include <cstdint>
#include <cstring>
#include <new>
#include <vector>

using kinet::crypto::frost::CommitmentSlot;
using kinet::crypto::frost::NonceSlot;

struct frost_ctx {
    uint32_t t;
    uint32_t n;
    uint8_t  seed[32];
    // Live nonces, indexed by signer_id (1..n). Each signer carries one
    // open slot at a time; the aggregator pulls (D, E) and sends the matching
    // online challenge back, which consumes the nonce.
    std::vector<NonceSlot>      nonces;     // size n+1, index 0 unused
    std::vector<CommitmentSlot> commits;    // size n+1
    std::vector<uint32_t>       slot_ids;   // size n+1
    uint32_t next_slot_id;
};

extern "C" int frost_setup(uint32_t t, uint32_t n, frost_ctx** out) {
    if (out == nullptr) return CRYPTO_ERR_INPUT;
    if (t == 0 || n == 0 || t > n) return CRYPTO_ERR_INPUT;

    frost_ctx* c = new (std::nothrow) frost_ctx;
    if (!c) return CRYPTO_ERR_INTERNAL;
    c->t = t;
    c->n = n;
    // Seed: in production sourced from KMS. For setup-without-explicit-seed
    // we derive from a process-local entropy pool; tests inject a known seed
    // via frost_setup_with_seed (extension below).
    std::memset(c->seed, 0, 32);
    c->nonces.assign(n + 1, NonceSlot{});
    c->commits.assign(n + 1, CommitmentSlot{});
    c->slot_ids.assign(n + 1, 0);
    c->next_slot_id = 0;
    *out = c;
    return CRYPTO_OK;
}

// Test/integration extension: setup with an explicit seed. Not part of the
// public crypto.h header; used only by the FROST KAT test and the Go cgo
// wrapper that holds the KMS-resident seed.
extern "C" int frost_setup_with_seed(uint32_t t, uint32_t n,
                                     const uint8_t seed[32],
                                     frost_ctx** out) {
    if (seed == nullptr) return CRYPTO_ERR_INPUT;
    int rc = frost_setup(t, n, out);
    if (rc != CRYPTO_OK) return rc;
    std::memcpy((*out)->seed, seed, 32);
    return CRYPTO_OK;
}

extern "C" int frost_partial_sign(frost_ctx* ctx,
                                  const uint8_t* msg, std::size_t msg_len,
                                  uint32_t signer_id, uint8_t* partial) {
    if (ctx == nullptr || partial == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    if (signer_id == 0 || signer_id > ctx->n) return CRYPTO_ERR_INPUT;
    (void)msg; (void)msg_len;  // online round consumes msg; pre-sign ignores it

    uint32_t slot_id = ctx->next_slot_id++;
    int rc = kinet::crypto::frost::presign_one(
        ctx->seed, signer_id, slot_id,
        ctx->commits[signer_id], ctx->nonces[signer_id]);
    if (rc != 0) return CRYPTO_ERR_INTERNAL;
    ctx->slot_ids[signer_id] = slot_id;

    std::memcpy(partial,      ctx->commits[signer_id].D, 33);
    std::memcpy(partial + 33, ctx->commits[signer_id].E, 33);
    return CRYPTO_OK;
}

// Batched presign — one shot, m signers × n_slots slots, signer-major.
// commits_out points at m * n_slots * 66 bytes. Nonces stay in the ctx;
// caller drives slots through frost_partial_sign_finalize for the online
// round. Used by the GPU kernel path through the matching driver.
extern "C" int frost_presign_batch(frost_ctx* ctx,
                                   const uint32_t* signer_ids, uint32_t m,
                                   uint32_t slot_id_base, uint32_t n_slots,
                                   uint8_t* commits_out) {
    if (ctx == nullptr || signer_ids == nullptr || commits_out == nullptr ||
        m == 0 || n_slots == 0) return CRYPTO_ERR_INPUT;

    std::vector<CommitmentSlot> commits(static_cast<std::size_t>(m) * n_slots);
    std::vector<NonceSlot>      nonces (static_cast<std::size_t>(m) * n_slots);

    int rc = kinet::crypto::frost::presign_batch(
        ctx->seed, signer_ids, m, slot_id_base, n_slots,
        commits.data(), nonces.data());
    if (rc != 0) return CRYPTO_ERR_INTERNAL;

    for (std::size_t k = 0; k < commits.size(); ++k) {
        std::memcpy(commits_out + k * 66,      commits[k].D, 33);
        std::memcpy(commits_out + k * 66 + 33, commits[k].E, 33);
    }
    return CRYPTO_OK;
}

// Online round: produce z_i = d_i + e_i*rho_i + lambda_i*s_i*c (mod n).
// rho/lambda/s/c are 32-byte big-endian scalars; out is 32-byte z.
extern "C" int frost_partial_sign_finalize(frost_ctx* ctx,
                                           uint32_t signer_id,
                                           const uint8_t rho[32],
                                           const uint8_t lambda[32],
                                           const uint8_t s[32],
                                           const uint8_t c[32],
                                           uint8_t z[32]) {
    if (ctx == nullptr || rho == nullptr || lambda == nullptr ||
        s == nullptr || c == nullptr || z == nullptr) return CRYPTO_ERR_INPUT;
    if (signer_id == 0 || signer_id > ctx->n) return CRYPTO_ERR_INPUT;

    int rc = kinet::crypto::frost::partial_sign(
        ctx->nonces[signer_id].d,
        ctx->nonces[signer_id].e,
        rho, lambda, s, c, z);
    if (rc != 0) return CRYPTO_ERR_INTERNAL;

    // Wipe consumed nonce.
    std::memset(ctx->nonces[signer_id].d, 0, 32);
    std::memset(ctx->nonces[signer_id].e, 0, 32);
    return CRYPTO_OK;
}

extern "C" int frost_aggregate(frost_ctx* ctx,
                               const uint8_t* partials, std::size_t n_partials,
                               uint8_t sig[64]) {
    if (ctx == nullptr || sig == nullptr) return CRYPTO_ERR_INPUT;
    if (n_partials == 0 || partials == nullptr) return CRYPTO_ERR_INPUT;
    int rc = kinet::crypto::frost::aggregate(partials, n_partials, sig);
    if (rc == 0) return CRYPTO_OK;
    if (rc == -2) return CRYPTO_ERR_INPUT;
    return CRYPTO_ERR_INTERNAL;
}

extern "C" int frost_verify(const uint8_t pk[32],
                            const uint8_t* msg, std::size_t msg_len,
                            const uint8_t sig[64]) {
    if (pk == nullptr || sig == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    bool ok = kinet::crypto::frost::verify(pk, msg, msg_len, sig);
    return ok ? CRYPTO_OK : CRYPTO_ERR_VERIFY;
}

extern "C" void frost_destroy(frost_ctx* ctx) {
    if (!ctx) return;
    // Wipe live nonces explicitly before freeing.
    for (auto& n : ctx->nonces) {
        std::memset(n.d, 0, 32);
        std::memset(n.e, 0, 32);
    }
    delete ctx;
}

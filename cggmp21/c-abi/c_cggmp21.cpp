// CGGMP21 C-ABI shim.
//
// Surface:
//   * setup           : wired (stores t, n, seed)
//   * partial_sign    : wired for the secp256k1 portion (R_i = k_i * G);
//                       Paillier ciphertext + ZK proof wire layout pinned.
//
// Aggregation and final ECDSA verification are deliberately not in the
// C-ABI: aggregation is network-bound (host-side coordinator) and final
// verification is plain secp256k1 ECDSA (use secp256k1_verify).
//
// The kernel emits a fixed-size record (PresignRecord) per (signer, slot)
// so the aggregator can stream presignatures from a GPU queue without a
// secondary parse step. Identifiable abort: PresignRecord::status names a
// signer to exclude when the ZK proof later fails to verify.

#include "crypto.h"

#include "../cpp/presign.hpp"

#include <cstdint>
#include <cstring>
#include <new>
#include <vector>

using kinet::crypto::cggmp21::PresignRecord;
using kinet::crypto::cggmp21::PresignSecret;
using kinet::crypto::cggmp21::PaillierKey;

struct cggmp21_ctx {
    uint32_t t;
    uint32_t n;
    uint8_t  seed[32];
    std::vector<PaillierKey>     paillier_keys;  // n+1 entries
    std::vector<PresignRecord>   records;        // n+1
    std::vector<PresignSecret>   secrets;        // n+1
    uint32_t next_slot_id;
};

extern "C" int cggmp21_setup(uint32_t t, uint32_t n, cggmp21_ctx** out) {
    if (out == nullptr) return CRYPTO_ERR_INPUT;
    if (t == 0 || n == 0 || t > n) return CRYPTO_ERR_INPUT;
    cggmp21_ctx* c = new (std::nothrow) cggmp21_ctx;
    if (!c) return CRYPTO_ERR_INTERNAL;
    c->t = t;
    c->n = n;
    std::memset(c->seed, 0, 32);
    c->paillier_keys.assign(n + 1, PaillierKey{});
    c->records.assign(n + 1, PresignRecord{});
    c->secrets.assign(n + 1, PresignSecret{});
    c->next_slot_id = 0;
    *out = c;
    return CRYPTO_OK;
}

extern "C" int cggmp21_setup_with_seed(uint32_t t, uint32_t n,
                                       const uint8_t seed[32],
                                       cggmp21_ctx** out) {
    if (seed == nullptr) return CRYPTO_ERR_INPUT;
    int rc = cggmp21_setup(t, n, out);
    if (rc != CRYPTO_OK) return rc;
    std::memcpy((*out)->seed, seed, 32);
    return CRYPTO_OK;
}

// Per-signer single slot — emits the public PresignRecord (881 bytes
// = 33 + 512 + 512 + (512+32+256+256+32) + 1 + 7 padding when fully wired;
// the secp256k1 portion alone is 33 bytes at offset 0).
extern "C" int cggmp21_partial_sign(cggmp21_ctx* ctx,
                                    const uint8_t* msg, std::size_t msg_len,
                                    uint32_t signer_id, uint8_t* partial) {
    if (ctx == nullptr || partial == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    if (signer_id == 0 || signer_id > ctx->n) return CRYPTO_ERR_INPUT;
    (void)msg; (void)msg_len;  // Online round consumes msg; pre-sign doesn't.

    uint32_t slot_id = ctx->next_slot_id++;
    int rc = kinet::crypto::cggmp21::presign_one(
        ctx->seed, ctx->paillier_keys[signer_id], signer_id, slot_id,
        ctx->records[signer_id], ctx->secrets[signer_id]);
    if (rc != 0) return CRYPTO_ERR_INTERNAL;

    std::memcpy(partial, &ctx->records[signer_id], sizeof(PresignRecord));
    return CRYPTO_OK;
}

// Batched form. records_out points at sizeof(PresignRecord) * m * n_slots
// bytes.
extern "C" int cggmp21_presign_batch(cggmp21_ctx* ctx,
                                     const uint32_t* signer_ids, uint32_t m,
                                     uint32_t slot_id_base, uint32_t n_slots,
                                     uint8_t* records_out) {
    if (!ctx || !signer_ids || !records_out || m == 0 || n_slots == 0)
        return CRYPTO_ERR_INPUT;

    std::vector<PresignRecord> recs((std::size_t)m * n_slots);
    std::vector<PresignSecret> secs((std::size_t)m * n_slots);
    std::vector<PaillierKey>   pks(m);
    for (uint32_t i = 0; i < m; ++i) {
        if (signer_ids[i] == 0 || signer_ids[i] > ctx->n) return CRYPTO_ERR_INPUT;
        pks[i] = ctx->paillier_keys[signer_ids[i]];
    }
    int rc = kinet::crypto::cggmp21::presign_batch(
        ctx->seed, pks.data(), signer_ids, m, slot_id_base, n_slots,
        recs.data(), secs.data());
    if (rc != 0) return CRYPTO_ERR_INTERNAL;

    // Records are POD; raw memcpy preserves the wire format.
    std::memcpy(records_out, recs.data(), recs.size() * sizeof(PresignRecord));
    return CRYPTO_OK;
}

extern "C" void cggmp21_destroy(cggmp21_ctx* ctx) {
    if (!ctx) return;
    // Wipe live secrets explicitly.
    for (auto& s : ctx->secrets) {
        std::memset(&s, 0, sizeof(s));
    }
    delete ctx;
}

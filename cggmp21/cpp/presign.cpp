// CGGMP21 batched pre-signing kernel — CPU canonical body.
//
// Wired:
//   - HKDF-SHA256(seed, signer_id || slot_id) -> (k_i, γ_i, ρ_k, ρ_g, α, β)
//   - R_i  = k_i * G                              (secp256k1, compressed sec1)
//   - K_i  = Paillier_enc(k_i, ρ_k)               (4096-bit, via LP-163 Karatsuba)
//   - G_i  = Paillier_enc(γ_i, ρ_g)               (4096-bit)
//   - Π^enc proof binding (K_i, k_i, ρ_k)         (CGGMP21 §A.6 simplified)
//
// All randomness (k, γ, ρ_k, ρ_g, α, β) is derived from HKDF-SHA256 over
// (seed, signer_id, slot_id) so the kernel is deterministic — same input,
// same output across CPU and GPU. The aggregator gets a status=0 record
// when the proof was emitted; the abort path is reserved for verifier-side
// failures only.

#include "presign.hpp"
#include "paillier.hpp"

#include "../../sha256/cpp/sha256.hpp"
#include "../../secp256k1/cpp/curve.hpp"
#include "../../secp256k1/cpp/field.hpp"

#include <cstring>

namespace kinet::crypto::cggmp21 {
namespace {

using kinet::crypto::secp256k1::U256;
using kinet::crypto::secp256k1::AffinePoint;
using kinet::crypto::secp256k1::JacobianPoint;
using kinet::crypto::secp256k1::N;
using kinet::crypto::secp256k1::GX;
using kinet::crypto::secp256k1::GY;

constexpr std::size_t SHA256_BLK = 64;

inline void sha256(uint8_t out[32], const uint8_t* d, std::size_t n) {
    cevm::crypto::sha256(reinterpret_cast<std::byte*>(out),
                         reinterpret_cast<const std::byte*>(d), n);
}

void hmac_sha256(uint8_t out[32],
                 const uint8_t* key, std::size_t key_len,
                 const uint8_t* msg, std::size_t msg_len) {
    uint8_t k[SHA256_BLK];
    std::memset(k, 0, sizeof(k));
    if (key_len > SHA256_BLK) sha256(k, key, key_len);
    else if (key_len > 0)     std::memcpy(k, key, key_len);
    uint8_t ipad[SHA256_BLK], opad[SHA256_BLK];
    for (std::size_t i = 0; i < SHA256_BLK; ++i) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    uint8_t inner_buf[SHA256_BLK + 256];
    std::memcpy(inner_buf, ipad, SHA256_BLK);
    if (msg_len > 0) {
        // Bounded use only — caller never exceeds 256 bytes.
        std::memcpy(inner_buf + SHA256_BLK, msg, msg_len);
    }
    uint8_t inner_hash[32];
    sha256(inner_hash, inner_buf, SHA256_BLK + msg_len);
    uint8_t outer[SHA256_BLK + 32];
    std::memcpy(outer, opad, SHA256_BLK);
    std::memcpy(outer + SHA256_BLK, inner_hash, 32);
    sha256(out, outer, SHA256_BLK + 32);
}

void hkdf_extract(uint8_t prk[32],
                  const uint8_t* salt, std::size_t salt_len,
                  const uint8_t* ikm, std::size_t ikm_len) {
    hmac_sha256(prk, salt, salt_len, ikm, ikm_len);
}

void hkdf_expand_64(uint8_t out64[64],
                    const uint8_t prk[32],
                    const uint8_t* info, std::size_t info_len) {
    uint8_t buf[32 + 64 + 1];
    // T(1)
    if (info_len) std::memcpy(buf, info, info_len);
    buf[info_len] = 0x01;
    uint8_t T1[32];
    hmac_sha256(T1, prk, 32, buf, info_len + 1);
    std::memcpy(out64, T1, 32);
    // T(2)
    std::memcpy(buf, T1, 32);
    if (info_len) std::memcpy(buf + 32, info, info_len);
    buf[32 + info_len] = 0x02;
    uint8_t T2[32];
    hmac_sha256(T2, prk, 32, buf, 32 + info_len + 1);
    std::memcpy(out64 + 32, T2, 32);
}

bool be32_to_scalar(const uint8_t in[32], uint8_t out[32]) {
    U256 v = U256::from_be32(in);
    int cmp = U256::cmp(v, N);
    if (cmp >= 0) {
        uint64_t bw;
        v = kinet::crypto::secp256k1::sub_256(v, N, bw);
    }
    if (v.is_zero()) return false;
    v.to_be32(out);
    return true;
}

void scalar_mul_base_compressed(const uint8_t k_be[32], uint8_t out33[33]) {
    U256 k = U256::from_be32(k_be);
    AffinePoint G;
    G.x = kinet::crypto::secp256k1::to_mont_p(GX);
    G.y = kinet::crypto::secp256k1::to_mont_p(GY);
    G.infinity = false;
    JacobianPoint P = kinet::crypto::secp256k1::jac_mul(k, G);
    AffinePoint A = kinet::crypto::secp256k1::jacobian_to_affine(P);
    if (A.infinity) { std::memset(out33, 0, 33); return; }
    U256 x_plain = kinet::crypto::secp256k1::from_mont_p(A.x);
    U256 y_plain = kinet::crypto::secp256k1::from_mont_p(A.y);
    out33[0] = (y_plain.limbs[0] & 1) ? 0x03 : 0x02;
    x_plain.to_be32(out33 + 1);
}

}  // namespace

int presign_one(const uint8_t        seed[32],
                const PaillierKey&   pk,
                uint32_t             signer_id,
                uint32_t             slot_id,
                PresignRecord&       record_out,
                PresignSecret&       secret_out) noexcept {
    if (signer_id == 0) return -1;

    // Clear output to a known state so partial fill never leaks stale memory.
    std::memset(&record_out, 0, sizeof(record_out));
    std::memset(&secret_out, 0, sizeof(secret_out));

    // HKDF-Extract: salt = "cggmp21-presign-v1" (18 bytes), ikm = seed
    const uint8_t salt[] = "cggmp21-presign-v1";
    uint8_t prk[32];
    hkdf_extract(prk, salt, 18, seed, 32);

    // info = signer_id_le || slot_id_le || ctr_le, expand 64 bytes per round
    uint8_t info[12];
    info[0] = (uint8_t)(signer_id      ); info[1] = (uint8_t)(signer_id >>  8);
    info[2] = (uint8_t)(signer_id >> 16); info[3] = (uint8_t)(signer_id >> 24);
    info[4] = (uint8_t)(slot_id        ); info[5] = (uint8_t)(slot_id   >>  8);
    info[6] = (uint8_t)(slot_id   >> 16); info[7] = (uint8_t)(slot_id   >> 24);

    // Sample (k, gamma) until both in [1, n-1]. info[8..12] = ctr.
    uint8_t k_be[32], gamma_be[32];
    bool got_k = false, got_g = false;
    uint32_t ctr = 0;
    while (!(got_k && got_g)) {
        info[ 8] = (uint8_t)(ctr      );
        info[ 9] = (uint8_t)(ctr >>  8);
        info[10] = (uint8_t)(ctr >> 16);
        info[11] = (uint8_t)(ctr >> 24);
        uint8_t okm[64];
        hkdf_expand_64(okm, prk, info, 12);
        if (!got_k) got_k = be32_to_scalar(okm, k_be);
        if (!got_g) got_g = be32_to_scalar(okm + 32, gamma_be);
        if (++ctr > 1024) return -1;
    }

    std::memcpy(secret_out.k,     k_be,     32);
    std::memcpy(secret_out.gamma, gamma_be, 32);

    // R_i = k_i * G — secp256k1 portion, byte-equal to the GPU kernel.
    scalar_mul_base_compressed(k_be, record_out.R);

    // Detect zero-pk (caller hasn't provisioned a real Paillier key for this
    // signer): emit the secp256k1-only record with status=0xFF so the
    // aggregator can route around. Real callers provision pk via
    // paillier::keygen_from_seed once per signer, then drive presign with a
    // valid pk; that path produces status=0 records with real K/G_cmt/pi_enc.
    bool pk_provisioned = false;
    for (size_t i = 0; i < PAILLIER_BLINDBYTES; ++i) {
        if (pk.N[i] != 0) { pk_provisioned = true; break; }
    }
    if (!pk_provisioned) {
        record_out.status = 0xFF;
        return 0;
    }

    // Sample (rho_k, rho_g, alpha, beta) from the same HKDF stream so the
    // Paillier path is deterministic per-slot. Each is MOD_BYTES=256 bytes.
    static_assert(PAILLIER_BLINDBYTES == 256, "Paillier blind size assumed 256 B");

    uint8_t rho_k_be   [PAILLIER_BLINDBYTES] = {0};
    uint8_t rho_g_be   [PAILLIER_BLINDBYTES] = {0};
    uint8_t alpha_be   [PAILLIER_BLINDBYTES] = {0};
    uint8_t beta_be    [PAILLIER_BLINDBYTES] = {0};

    auto fill_blind = [&](uint8_t* dst, uint32_t base_ctr) {
        for (int blk = 0; blk < 4; ++blk) {
            uint32_t ictr = base_ctr + (uint32_t)blk;
            info[ 8] = (uint8_t)(ictr      );
            info[ 9] = (uint8_t)(ictr >>  8);
            info[10] = (uint8_t)(ictr >> 16);
            info[11] = (uint8_t)(ictr >> 24);
            uint8_t okm[64];
            hkdf_expand_64(okm, prk, info, 12);
            std::memcpy(dst + 64 * blk, okm, 64);
        }
    };
    fill_blind(rho_k_be, 0x10000);
    fill_blind(rho_g_be, 0x20000);
    fill_blind(alpha_be, 0x30000);
    fill_blind(beta_be,  0x40000);

    std::memcpy(secret_out.rho_k, rho_k_be, PAILLIER_BLINDBYTES);
    std::memcpy(secret_out.rho_g, rho_g_be, PAILLIER_BLINDBYTES);

    namespace pl = kinet::crypto::cggmp21::paillier;
    pl::PublicKey ppk;
    std::memcpy(ppk.N,    pk.N,    pl::MOD_BYTES);
    std::memcpy(ppk.N_sq, pk.N_sq, pl::MOD_SQ_BYTES);

    uint8_t k_padded[pl::MOD_BYTES]   = {0};
    uint8_t g_padded[pl::MOD_BYTES]   = {0};
    std::memcpy(k_padded + pl::MOD_BYTES - 32, k_be,     32);
    std::memcpy(g_padded + pl::MOD_BYTES - 32, gamma_be, 32);

    if (pl::encrypt(ppk, k_padded, rho_k_be, record_out.K)        != 0) return -1;
    if (pl::encrypt(ppk, g_padded, rho_g_be, record_out.G_cmt)    != 0) return -1;

    // Π^enc proof binding (record_out.K, k_i, rho_k_i).
    if (pl::pi_enc_prove(ppk, record_out.K, k_padded, rho_k_be,
                         alpha_be, beta_be, record_out.pi_enc) != 0) {
        return -1;
    }

    record_out.status = 0;  // Full record ready.
    return 0;
}

int presign_batch(const uint8_t            seed[32],
                  const PaillierKey*       pks,
                  const uint32_t*          signer_ids,
                  uint32_t                 m,
                  uint32_t                 slot_id_base,
                  uint32_t                 n_slots,
                  PresignRecord*           records_out,
                  PresignSecret*           secrets_out) noexcept {
    if (!seed || !pks || !signer_ids || !records_out || !secrets_out ||
        m == 0 || n_slots == 0) return -1;

    for (uint32_t i = 0; i < m; ++i) {
        if (signer_ids[i] == 0) return -1;
        for (uint32_t s = 0; s < n_slots; ++s) {
            std::size_t idx = (std::size_t)i * n_slots + s;
            int rc = presign_one(seed, pks[i], signer_ids[i],
                                 slot_id_base + s,
                                 records_out[idx], secrets_out[idx]);
            if (rc != 0) return rc;
        }
    }
    return 0;
}

}  // namespace kinet::crypto::cggmp21

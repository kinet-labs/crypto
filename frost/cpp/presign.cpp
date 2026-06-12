// FROST batched pre-signing kernel — CPU canonical body.
// Mirrors RFC 9591 (FROST(secp256k1, SHA-256)) round-1 nonce generation.

#include "presign.hpp"

#include "../../sha256/cpp/sha256.hpp"
#include "../../secp256k1/cpp/curve.hpp"
#include "../../secp256k1/cpp/field.hpp"

#include <cstring>

namespace kinet::crypto::frost {
namespace {

using kinet::crypto::secp256k1::U256;
using kinet::crypto::secp256k1::AffinePoint;
using kinet::crypto::secp256k1::JacobianPoint;
using kinet::crypto::secp256k1::N;
using kinet::crypto::secp256k1::GX;
using kinet::crypto::secp256k1::GY;

constexpr std::size_t SHA256_LEN = 32;
constexpr std::size_t SHA256_BLK = 64;

inline void sha256(uint8_t out[32], const uint8_t* data, std::size_t len) {
    cevm::crypto::sha256(reinterpret_cast<std::byte*>(out),
                         reinterpret_cast<const std::byte*>(data),
                         len);
}

// HMAC-SHA256, RFC 2104. Self-contained so the same body can be inlined into
// GPU kernels.
void hmac_sha256(uint8_t out[32],
                 const uint8_t* key, std::size_t key_len,
                 const uint8_t* msg, std::size_t msg_len) {
    uint8_t k[SHA256_BLK];
    std::memset(k, 0, sizeof(k));
    if (key_len > SHA256_BLK) {
        sha256(k, key, key_len);
    } else if (key_len > 0) {
        std::memcpy(k, key, key_len);
    }

    uint8_t ipad[SHA256_BLK], opad[SHA256_BLK];
    for (std::size_t i = 0; i < SHA256_BLK; ++i) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    // inner = SHA256(ipad || msg)
    uint8_t inner_buf_stack[SHA256_BLK + 256];
    uint8_t* inner = inner_buf_stack;
    bool heap = false;
    std::size_t inner_len = SHA256_BLK + msg_len;
    if (inner_len > sizeof(inner_buf_stack)) {
        inner = new uint8_t[inner_len];
        heap = true;
    }
    std::memcpy(inner, ipad, SHA256_BLK);
    if (msg_len) std::memcpy(inner + SHA256_BLK, msg, msg_len);
    uint8_t inner_hash[32];
    sha256(inner_hash, inner, inner_len);
    if (heap) delete[] inner;

    // outer = SHA256(opad || inner_hash)
    uint8_t outer[SHA256_BLK + 32];
    std::memcpy(outer, opad, SHA256_BLK);
    std::memcpy(outer + SHA256_BLK, inner_hash, 32);
    sha256(out, outer, SHA256_BLK + 32);
}

// HKDF-Extract per RFC 5869 §2.2.
inline void hkdf_extract(uint8_t prk[32],
                         const uint8_t* salt, std::size_t salt_len,
                         const uint8_t* ikm,  std::size_t ikm_len) {
    hmac_sha256(prk, salt, salt_len, ikm, ikm_len);
}

// HKDF-Expand per RFC 5869 §2.3, output length L bytes (L <= 255*32).
void hkdf_expand(uint8_t* out, std::size_t L,
                 const uint8_t prk[32],
                 const uint8_t* info, std::size_t info_len) {
    uint8_t T[32];
    uint8_t T_prev_buf[32 + 256 + 1];  // T(i-1) || info || counter
    std::size_t produced = 0;
    uint8_t counter = 1;
    std::size_t prev_len = 0;
    while (produced < L) {
        std::size_t off = 0;
        if (prev_len) { std::memcpy(T_prev_buf + off, T, prev_len); off += prev_len; }
        if (info_len) { std::memcpy(T_prev_buf + off, info, info_len); off += info_len; }
        T_prev_buf[off++] = counter;
        hmac_sha256(T, prk, 32, T_prev_buf, off);
        std::size_t take = (L - produced > 32) ? 32 : (L - produced);
        std::memcpy(out + produced, T, take);
        produced += take;
        prev_len = 32;
        ++counter;
    }
}

// Reduce a 32-byte big-endian integer modulo n, with rejection for the
// degenerate case (result == 0). Returns true if the value fell in
// [1, n-1] without rejection. Caller iterates HKDF until accept.
bool be32_to_scalar(const uint8_t in[32], uint8_t out[32]) {
    U256 v = U256::from_be32(in);
    // Reduce mod n: if v >= n, subtract n once. The HKDF output is uniform
    // in [0, 2^256), so the bias from a single subtraction is < 2^-128 —
    // RFC 9591 §4.1 explicitly tolerates this; we still reject the zero case.
    int cmp = U256::cmp(v, N);
    if (cmp >= 0) {
        uint64_t bw;
        v = kinet::crypto::secp256k1::sub_256(v, N, bw);
    }
    if (v.is_zero()) return false;
    v.to_be32(out);
    return true;
}

// Compute k * G. k is 32-byte big-endian, output is 33-byte compressed sec1.
void scalar_mul_base_compressed(const uint8_t k_be[32], uint8_t out33[33]) {
    U256 k = U256::from_be32(k_be);

    AffinePoint G;
    G.x = kinet::crypto::secp256k1::to_mont_p(GX);
    G.y = kinet::crypto::secp256k1::to_mont_p(GY);
    G.infinity = false;

    JacobianPoint P = kinet::crypto::secp256k1::jac_mul(k, G);
    AffinePoint A = kinet::crypto::secp256k1::jacobian_to_affine(P);

    if (A.infinity) {
        // k * G = O is impossible for k in [1, n-1].
        std::memset(out33, 0, 33);
        return;
    }

    U256 x_plain = kinet::crypto::secp256k1::from_mont_p(A.x);
    U256 y_plain = kinet::crypto::secp256k1::from_mont_p(A.y);
    out33[0] = (y_plain.limbs[0] & 1) ? 0x03 : 0x02;
    x_plain.to_be32(out33 + 1);
}

}  // namespace

int presign_one(const uint8_t seed[32],
                uint32_t signer_id,
                uint32_t slot_id,
                CommitmentSlot& commit_out,
                NonceSlot&      nonce_out) noexcept {
    if (signer_id == 0) return -1;  // FROST forbids id 0

    // HKDF-Extract: PRK = HMAC-SHA256(salt = "frost-presign-v1", ikm = seed)
    const uint8_t salt[] = "frost-presign-v1";  // 16 bytes + NUL; we use 16
    uint8_t prk[32];
    hkdf_extract(prk, salt, 16, seed, 32);

    // info = signer_id_le32 || slot_id_le32 || counter (loop salt for rejection)
    uint8_t info[12];
    info[0] = (uint8_t)(signer_id      ); info[1] = (uint8_t)(signer_id >> 8 );
    info[2] = (uint8_t)(signer_id >> 16); info[3] = (uint8_t)(signer_id >> 24);
    info[4] = (uint8_t)(slot_id        ); info[5] = (uint8_t)(slot_id   >> 8 );
    info[6] = (uint8_t)(slot_id   >> 16); info[7] = (uint8_t)(slot_id   >> 24);
    info[8]  = 0; info[9]  = 0; info[10] = 0; info[11] = 0;

    // Loop until both d and e are in [1, n-1]. Probability of any rejection
    // is < 2^-128 per round; in practice this loop runs once.
    uint8_t okm[64];
    uint8_t d_be[32], e_be[32];
    bool got_d = false, got_e = false;
    uint32_t ctr = 0;
    while (!(got_d && got_e)) {
        info[8]  = (uint8_t)(ctr      );
        info[9]  = (uint8_t)(ctr >> 8 );
        info[10] = (uint8_t)(ctr >> 16);
        info[11] = (uint8_t)(ctr >> 24);

        hkdf_expand(okm, 64, prk, info, 12);

        if (!got_d) got_d = be32_to_scalar(okm,      d_be);
        if (!got_e) got_e = be32_to_scalar(okm + 32, e_be);
        ++ctr;
        if (ctr > 1024) return -1;  // pathological, should never trigger
    }

    // Commitments. Constant-time scalar mul (jac_mul always doubles).
    scalar_mul_base_compressed(d_be, commit_out.D);
    scalar_mul_base_compressed(e_be, commit_out.E);

    std::memcpy(nonce_out.d, d_be, 32);
    std::memcpy(nonce_out.e, e_be, 32);
    return 0;
}

int presign_batch(const uint8_t       seed[32],
                  const uint32_t*     signer_ids,
                  uint32_t            m,
                  uint32_t            slot_id_base,
                  uint32_t            n,
                  CommitmentSlot*     commits_out,
                  NonceSlot*          nonces_out) noexcept {
    if (seed == nullptr || signer_ids == nullptr ||
        commits_out == nullptr || nonces_out == nullptr ||
        m == 0 || n == 0) return -1;

    // Outer loop is signer-major so the row layout matches the GPU kernel
    // (one threadgroup per signer × N slots).
    for (uint32_t i = 0; i < m; ++i) {
        if (signer_ids[i] == 0) return -1;
        for (uint32_t s = 0; s < n; ++s) {
            std::size_t idx = (std::size_t)i * n + s;
            int rc = presign_one(seed, signer_ids[i], slot_id_base + s,
                                 commits_out[idx], nonces_out[idx]);
            if (rc != 0) return rc;
        }
    }
    return 0;
}

int partial_sign(const uint8_t d[32],
                 const uint8_t e[32],
                 const uint8_t rho[32],
                 const uint8_t lambda[32],
                 const uint8_t s[32],
                 const uint8_t c[32],
                 uint8_t       z_out[32]) noexcept {
    if (!d || !e || !rho || !lambda || !s || !c || !z_out) return -1;

    // Convert to Montgomery form on Fn for constant-time fn_mul.
    using namespace kinet::crypto::secp256k1;
    U256 D     = to_mont_n(U256::from_be32(d));
    U256 E     = to_mont_n(U256::from_be32(e));
    U256 RHO   = to_mont_n(U256::from_be32(rho));
    U256 LAMB  = to_mont_n(U256::from_be32(lambda));
    U256 S     = to_mont_n(U256::from_be32(s));
    U256 C     = to_mont_n(U256::from_be32(c));

    U256 e_rho      = fn_mul(E, RHO);             // e * rho
    U256 lamb_s     = fn_mul(LAMB, S);            // lambda * s
    U256 lamb_s_c   = fn_mul(lamb_s, C);          // lambda * s * c
    U256 z_mont     = fn_add(D, fn_add(e_rho, lamb_s_c));

    U256 z_plain = from_mont_n(z_mont);
    z_plain.to_be32(z_out);
    return 0;
}

}  // namespace kinet::crypto::frost

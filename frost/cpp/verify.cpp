// FROST verify — BIP-340-style Schnorr verification on the
// FROST(secp256k1, SHA-256) ciphersuite. See verify.hpp.

#include "verify.hpp"

#include "../../secp256k1/cpp/curve.hpp"
#include "../../secp256k1/cpp/field.hpp"

#include <cstring>

namespace kinet::crypto::frost {

namespace {

using kinet::crypto::secp256k1::U256;
using kinet::crypto::secp256k1::AffinePoint;
using kinet::crypto::secp256k1::JacobianPoint;
using kinet::crypto::secp256k1::N;
using kinet::crypto::secp256k1::P;
using kinet::crypto::secp256k1::GX;
using kinet::crypto::secp256k1::GY;

// SHA-256 from the public C-ABI; declared here to avoid pulling crypto.h.
extern "C" int sha256(const uint8_t* in, size_t in_len, uint8_t out[32]);

// BIP-340 lift_x: given x in [0, p), find P = (x, y) on y^2 = x^3 + 7 with
// even y. Returns true on success.
bool lift_x_even(const uint8_t x_be[32], AffinePoint& out) noexcept {
    using namespace kinet::crypto::secp256k1;
    U256 x_norm = U256::from_be32(x_be);
    if (U256::cmp(x_norm, P) >= 0) return false;

    U256 x_mont = to_mont_p(x_norm);
    U256 x2 = fp_sqr(x_mont);
    U256 x3 = fp_mul(x2, x_mont);
    U256 seven_mont = to_mont_p(U256{7, 0, 0, 0});
    U256 y2 = fp_add(x3, seven_mont);

    U256 y_mont;
    if (!fp_sqrt(y2, y_mont)) return false;

    U256 y_norm = from_mont_p(y_mont);
    if ((y_norm.limbs[0] & 1ULL) != 0) {
        // y is odd; flip to even by negating mod p.
        U256 zero{};
        y_mont = fp_sub(zero, y_mont);
    }
    out.x = x_mont;
    out.y = y_mont;
    out.infinity = false;
    return true;
}

// BIP-340 challenge: c = SHA256(R_x || pk_x || msg) reduced mod n.
U256 challenge(const uint8_t R_x[32], const uint8_t pk_x[32],
               const uint8_t* msg, std::size_t msg_len) noexcept {
    // For FROST(secp256k1, SHA-256) the challenge is plain SHA-256 of the
    // concatenation. RFC 9591 §5.1 specifies SHA-256 with no domain tag at
    // this layer — the per-protocol tag is folded into the binding factor
    // upstream. Caller-supplied msg may itself be a tagged hash.
    using kinet::crypto::secp256k1::sub_256;
    constexpr std::size_t HEADER = 64;
    std::vector<uint8_t> buf;
    buf.reserve(HEADER + msg_len);
    buf.insert(buf.end(), R_x, R_x + 32);
    buf.insert(buf.end(), pk_x, pk_x + 32);
    if (msg_len > 0) buf.insert(buf.end(), msg, msg + msg_len);

    uint8_t h[32];
    sha256(buf.data(), buf.size(), h);

    // Reduce mod n once (h is < 2^256, n is just below 2^256, one cond_sub).
    U256 c = U256::from_be32(h);
    if (U256::cmp(c, N) >= 0) {
        uint64_t bw;
        c = sub_256(c, N, bw);
    }
    return c;
}

}  // namespace

bool verify(const uint8_t pk[32], const uint8_t* msg, std::size_t msg_len,
            const uint8_t sig[64]) noexcept {
    using namespace kinet::crypto::secp256k1;
    if (pk == nullptr || sig == nullptr) return false;
    if (msg_len > 0 && msg == nullptr) return false;

    // Parse sig into R_x, z.
    const uint8_t* R_x = sig + 0;
    const uint8_t* z_be = sig + 32;

    // Decode z as plain integer in [0, n).
    U256 z = U256::from_be32(z_be);
    if (U256::cmp(z, N) >= 0) return false;

    // Lift pk and R to even-y points on the curve.
    AffinePoint Pkey, R;
    if (!lift_x_even(pk, Pkey)) return false;
    if (!lift_x_even(R_x, R))    return false;

    // c = H(R_x || pk_x || msg) mod n.
    U256 c = challenge(R_x, pk, msg, msg_len);

    // Compute z * G - c * Pkey, check it equals R.
    AffinePoint G;
    G.x = to_mont_p(GX);
    G.y = to_mont_p(GY);
    G.infinity = false;

    JacobianPoint zG = jac_mul(z, G);
    JacobianPoint cP = jac_mul(c, Pkey);

    // R_recomputed = z*G + (-c*Pkey)
    // Negate cP by negating its Y in Montgomery (P - cP.Y), then add.
    JacobianPoint neg_cP = cP;
    if (!cP.infinity) {
        U256 zero{};
        neg_cP.Y = fp_sub(zero, cP.Y);
    }
    JacobianPoint R_check = jac_add(zG, neg_cP);
    if (R_check.infinity) return false;

    AffinePoint R_check_aff = jacobian_to_affine(R_check);

    // Compare x coords.
    return R.x == R_check_aff.x;
}

}  // namespace kinet::crypto::frost

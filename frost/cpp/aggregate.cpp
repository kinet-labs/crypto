// FROST aggregate — combines per-signer commitments + partials into a 64-byte
// BIP-340-style Schnorr signature on secp256k1. See aggregate.hpp for layout.

#include "aggregate.hpp"

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

// Decompress a 33-byte sec1 point. prefix 0x02 -> even y, 0x03 -> odd y.
// Returns true on success and populates `out` in Montgomery form.
bool decompress(const uint8_t in33[33], AffinePoint& out) noexcept {
    using namespace kinet::crypto::secp256k1;
    if (in33[0] != 0x02 && in33[0] != 0x03) return false;

    U256 x_norm = U256::from_be32(in33 + 1);
    if (U256::cmp(x_norm, P) >= 0) return false;

    U256 x_mont = to_mont_p(x_norm);
    U256 x2 = fp_sqr(x_mont);
    U256 x3 = fp_mul(x2, x_mont);
    U256 seven_mont = to_mont_p(U256{7, 0, 0, 0});
    U256 y2 = fp_add(x3, seven_mont);

    U256 y_mont;
    if (!fp_sqrt(y2, y_mont)) return false;

    U256 y_norm = from_mont_p(y_mont);
    bool y_is_odd = (y_norm.limbs[0] & 1ULL) != 0;
    bool want_odd = (in33[0] == 0x03);
    if (y_is_odd != want_odd) {
        // y := p - y  (in Montgomery: 0 - y_mont mod p)
        U256 zero{};
        y_mont = fp_sub(zero, y_mont);
    }

    out.x = x_mont;
    out.y = y_mont;
    out.infinity = false;
    return true;
}

// Reduce (x, y) Jacobian point to BIP-340 x-only encoding. Adjusts y to even
// (negates the point if y is odd) so the verifier can lift_x with even-y.
// Writes 32 bytes of x in big-endian. Returns false if point is at infinity.
bool to_xonly(const JacobianPoint& P_in, uint8_t out_xonly[32]) noexcept {
    using namespace kinet::crypto::secp256k1;
    AffinePoint A = jacobian_to_affine(P_in);
    if (A.infinity) return false;
    U256 x_norm = from_mont_p(A.x);
    x_norm.to_be32(out_xonly);
    // BIP-340 even-y normalization is part of the verify lift; for
    // aggregation we only emit x, the verifier picks even-y.
    return true;
}

// rho * E (where rho is a plain 32-byte BE scalar, E in Montgomery affine).
JacobianPoint scalar_mul_affine(const uint8_t rho_be[32],
                                const AffinePoint& E) noexcept {
    using namespace kinet::crypto::secp256k1;
    U256 rho = U256::from_be32(rho_be);
    return jac_mul(rho, E);
}

}  // namespace

int aggregate(const uint8_t* partials,
              std::size_t    n_partials,
              uint8_t        sig_out[64]) noexcept {
    if (sig_out == nullptr) return -1;
    if (n_partials == 0 || partials == nullptr) return -1;

    using namespace kinet::crypto::secp256k1;

    // Aggregate point R = sum_i (D_i + rho_i * E_i)
    JacobianPoint R = jac_zero();

    // Aggregate response z = sum_i z_i (mod n). Accumulate in Montgomery
    // for fewer add reductions; the conversion back is one fn_mul.
    U256 z_acc_mont = to_mont_n(U256{});  // 0 in Montgomery == 0
    // (to_mont_n(0) is just 0 since Montgomery-of-zero is zero)

    for (std::size_t i = 0; i < n_partials; ++i) {
        const uint8_t* base = partials + i * FROST_PARTIAL_LEN;
        const uint8_t* D33  = base;
        const uint8_t* E33  = base + 33;
        const uint8_t* z32  = base + 66;
        const uint8_t* rho32 = base + 98;

        AffinePoint D, E;
        if (!decompress(D33, D)) return -2;
        if (!decompress(E33, E)) return -2;

        // R += D_i + rho_i * E_i
        JacobianPoint rho_E = scalar_mul_affine(rho32, E);
        R = jac_add_mixed(R, D);
        R = jac_add(R, rho_E);

        // z_acc += z_i (in Fn). z_i is already < n by protocol invariant; we
        // don't enforce here — verify will reject any out-of-range aggregate.
        U256 z_i = U256::from_be32(z32);
        z_acc_mont = fn_add(z_acc_mont, to_mont_n(z_i));
    }

    if (R.infinity) return -3;

    // Encode R as x-only.
    AffinePoint Ra = jacobian_to_affine(R);
    if (Ra.infinity) return -3;

    // BIP-340 even-y: if R has odd y, the verifier lifts even-y so we must
    // negate z to keep z*G == R + c*pk valid. Equivalently, if R.y is odd,
    // negate z (mod n) before encoding.
    U256 Ry_norm = from_mont_p(Ra.y);
    bool R_y_odd = (Ry_norm.limbs[0] & 1ULL) != 0;

    U256 z_plain = from_mont_n(z_acc_mont);
    if (R_y_odd) {
        // z := n - z (mod n)
        if (!z_plain.is_zero()) {
            uint64_t bw;
            z_plain = sub_256(N, z_plain, bw);
        }
    }

    U256 Rx_norm = from_mont_p(Ra.x);
    Rx_norm.to_be32(sig_out);
    z_plain.to_be32(sig_out + 32);
    return 0;
}

}  // namespace kinet::crypto::frost

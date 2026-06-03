// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// First-party secp256k1 ECDSA public-key recovery.
//
// Public C ABI: kinet/crypto/secp256k1.h
//
// Algorithm (standard ecrecover):
//   given (hash, r, s, v):
//     1. validate r, s in [1, n-1] and v in {0, 1}
//     2. lift r to point R on curve with y-parity v:
//          y^2 = r^3 + 7 mod p; pick y with parity v
//     3. compute u1 = -e * r^-1 mod n,  u2 = s * r^-1 mod n
//     4. Q = u1 * G + u2 * R
//     5. if Q == O: fail. else output Q.x || Q.y as 64-byte uncompressed pubkey.
//
// No external dependencies. Lives entirely on top of field.hpp + curve.hpp.

#include "kinet/crypto/secp256k1.h"
#include "field.hpp"
#include "curve.hpp"

#include <cstring>

namespace lc = kinet::crypto::secp256k1;

extern "C" kinet_secp256k1_status kinet_secp256k1_ecrecover(
    const uint8_t hash[32],
    const uint8_t r_be[32],
    const uint8_t s_be[32],
    uint8_t v,
    uint8_t pubkey[64]) {

    if (!hash || !r_be || !s_be || !pubkey) return KINET_SECP256K1_ERR_NULL_ARG;

    // Normalize v: accept {0, 1, 27, 28} and EIP-155 chain-id encodings.
    if (v >= 27) v -= 27;
    if (v > 1) v %= 2;

    lc::U256 r = lc::U256::from_be32(r_be);
    lc::U256 s = lc::U256::from_be32(s_be);
    lc::U256 e = lc::U256::from_be32(hash);

    // r in [1, n-1]
    if (r.is_zero() || lc::U256::cmp(r, lc::N) >= 0) return KINET_SECP256K1_ERR_INVALID_R;
    // s in [1, n-1]
    if (s.is_zero() || lc::U256::cmp(s, lc::N) >= 0) return KINET_SECP256K1_ERR_INVALID_S;
    if (v > 1) return KINET_SECP256K1_ERR_INVALID_V;

    // Step 2: lift r to point R on curve. Compute y^2 = r^3 + 7 mod p.
    lc::U256 r_p_mont = lc::to_mont_p(r);
    lc::U256 r2_mont = lc::fp_sqr(r_p_mont);
    lc::U256 r3_mont = lc::fp_mul(r2_mont, r_p_mont);
    lc::U256 seven{7, 0, 0, 0};
    lc::U256 seven_mont = lc::to_mont_p(seven);
    lc::U256 y2_mont = lc::fp_add(r3_mont, seven_mont);

    lc::U256 y_mont;
    if (!lc::fp_sqrt(y2_mont, y_mont)) return KINET_SECP256K1_ERR_NO_SQRT;

    // Pick the y with the requested parity.
    lc::U256 y_normal = lc::from_mont_p(y_mont);
    bool y_is_odd = (y_normal.limbs[0] & 1ULL) != 0;
    bool want_odd = (v == 1);
    if (y_is_odd != want_odd) {
        // y = p - y (in Montgomery form: 0 - y_mont mod p)
        lc::U256 zero{};
        y_mont = lc::fp_sub(zero, y_mont);
    }

    lc::AffinePoint R;
    R.x = r_p_mont; R.y = y_mont; R.infinity = false;

    // Step 3: u1 = -e * r^-1 mod n,  u2 = s * r^-1 mod n
    // Reduce e mod n first (RFC 6979 §2.3.2).
    lc::U256 e_red = e;
    if (lc::U256::cmp(e_red, lc::N) >= 0) {
        uint64_t bw;
        e_red = lc::sub_256(e_red, lc::N, bw);
    }

    lc::U256 r_n_mont = lc::to_mont_n(r);
    lc::U256 r_inv_n_mont = lc::fn_inv(r_n_mont);

    lc::U256 e_n_mont = lc::to_mont_n(e_red);
    lc::U256 s_n_mont = lc::to_mont_n(s);

    // u1 = -(e * r_inv) mod n
    lc::U256 u1_n_mont = lc::fn_mul(e_n_mont, r_inv_n_mont);
    lc::U256 u1 = lc::from_mont_n(u1_n_mont);
    if (!u1.is_zero()) {
        uint64_t bw;
        u1 = lc::sub_256(lc::N, u1, bw);
    }

    // u2 = s * r_inv mod n
    lc::U256 u2 = lc::from_mont_n(lc::fn_mul(s_n_mont, r_inv_n_mont));

    // Step 4: Q = u1 * G + u2 * R.
    lc::AffinePoint G;
    G.x = lc::to_mont_p(lc::GX);
    G.y = lc::to_mont_p(lc::GY);
    G.infinity = false;

    lc::JacobianPoint Q = lc::jac_msm2(u1, G, u2, R);
    lc::AffinePoint Qa = lc::jacobian_to_affine(Q);
    if (Qa.infinity) return KINET_SECP256K1_ERR_AT_INFINITY;

    // Output Q.x || Q.y as 64 bytes big-endian, normal (non-Montgomery) form.
    lc::U256 qx = lc::from_mont_p(Qa.x);
    lc::U256 qy = lc::from_mont_p(Qa.y);
    qx.to_be32(pubkey);
    qy.to_be32(pubkey + 32);

    return KINET_SECP256K1_OK;
}

extern "C" kinet_secp256k1_status kinet_secp256k1_ecrecover_verify(
    const uint8_t hash[32],
    const uint8_t r[32],
    const uint8_t s[32],
    uint8_t v,
    const uint8_t expected_pubkey[64]) {

    if (!expected_pubkey) return KINET_SECP256K1_ERR_NULL_ARG;
    uint8_t got[64];
    auto st = kinet_secp256k1_ecrecover(hash, r, s, v, got);
    if (st != KINET_SECP256K1_OK) return st;
    if (std::memcmp(got, expected_pubkey, 64) != 0) return KINET_SECP256K1_ERR_AT_INFINITY;
    return KINET_SECP256K1_OK;
}

extern "C" kinet_secp256k1_status kinet_secp256k1_ecrecover_batch(
    const uint8_t* inputs,
    size_t n,
    uint8_t* out_pk,
    uint8_t* out_st) {

    if (!inputs || !out_pk || !out_st) return KINET_SECP256K1_ERR_NULL_ARG;

    for (size_t i = 0; i < n; ++i) {
        const uint8_t* base = inputs + i * 97;
        const uint8_t* hash = base;
        const uint8_t* r_be = base + 32;
        const uint8_t* s_be = base + 64;
        uint8_t v = base[96];

        auto st = kinet_secp256k1_ecrecover(hash, r_be, s_be, v, out_pk + i * 64);
        out_st[i] = (uint8_t)st;
    }
    return KINET_SECP256K1_OK;
}

// 7-stage ecrecover pipeline (see crypto/secp256k1/gpu/metal/ecrecover_pipeline.metal
// for the matching GPU kernels). The CPU path here is the canonical reference
// the GPU must match byte-for-byte.
//
// Stages, one per micro-kernel:
//   1. parse_reject       -- parse 65-byte sig, reject malformed
//   2. field_normalize    -- sqrt(r^3 + 7) via Tonelli-Shanks (p ≡ 3 mod 4)
//   3. recover_R          -- pick correct y by parity v
//   4. scalar_mult_u1u2   -- u1 = -m * r^-1; u2 = s * r^-1; per-sig field work
//   5. jacobian_add       -- combine u1*G + u2*R
//   6. address_keccak     -- keccak(pubkey)[12:32] -> 20-byte address
//   7. compose_output     -- write pubkey or address
//
// The win comes from Stage A's Montgomery batch inversion: instead of N Fermat
// inversions for r^-1 (one per signature), we do one Fermat inversion plus
// 3N field multiplications. Same for the Jacobian-to-affine Z^-1 sweep.

#pragma once

#include "kinet/crypto/secp256k1.h"
#include "kinet/crypto/keccak.h"

#include "field.hpp"
#include "curve.hpp"
#include "batch_inv.hpp"
#include "windowed_g_table.hpp"

#include <cstdint>
#include <cstring>
#include <vector>

namespace kinet::crypto::secp256k1 {

// Per-signature parsed work item.
struct EcrecoverWorkItem {
    U256     hash_e;       // message hash (raw, may exceed n)
    U256     r;            // big-endian-decoded r
    U256     s;            // big-endian-decoded s
    uint8_t  v_norm;       // normalized recovery id 0 or 1
    uint8_t  status;       // SECP256K1_OK on success, error code otherwise
    U256     r_n_mont;     // Montgomery encoding of r mod n  (for batch inv)
    U256     r_inv_n_mont; // r^-1 mod n in Montgomery form   (filled by stage 4)
    AffinePoint R_pt;      // recovered R = (r_p, y) in Montgomery form
    JacobianPoint Q;       // u1*G + u2*R combined
    AffinePoint Q_aff;     // affine final
};

// Stage 1: parse + range-validate, normalize v.
inline void stage_parse_reject(size_t n, const uint8_t* hashes, const uint8_t* sigs,
                               EcrecoverWorkItem* items) {
    for (size_t i = 0; i < n; ++i) {
        EcrecoverWorkItem& it = items[i];
        const uint8_t* h = hashes + i * 32;
        const uint8_t* sig = sigs + i * 65;

        it.hash_e = U256::from_be32(h);
        it.r      = U256::from_be32(sig);
        it.s      = U256::from_be32(sig + 32);
        uint8_t v = sig[64];
        if (v >= 27) v -= 27;
        if (v > 1) v %= 2;
        it.v_norm = v;
        it.status = SECP256K1_OK;

        if (it.r.is_zero() || U256::cmp(it.r, N) >= 0) { it.status = SECP256K1_ERR_INVALID_R; continue; }
        if (it.s.is_zero() || U256::cmp(it.s, N) >= 0) { it.status = SECP256K1_ERR_INVALID_S; continue; }
        if (sig[64] != 0 && sig[64] != 1 && sig[64] != 27 && sig[64] != 28) {
            it.status = SECP256K1_ERR_INVALID_V; continue;
        }
    }
}

// Stage 2: lift x = r to point R via y^2 = x^3 + 7 mod p.
inline void stage_field_normalize(size_t n, EcrecoverWorkItem* items) {
    for (size_t i = 0; i < n; ++i) {
        EcrecoverWorkItem& it = items[i];
        if (it.status != SECP256K1_OK) continue;

        U256 r_p_mont = to_mont_p(it.r);
        U256 r2_mont  = fp_sqr(r_p_mont);
        U256 r3_mont  = fp_mul(r2_mont, r_p_mont);
        U256 seven{7, 0, 0, 0};
        U256 seven_mont = to_mont_p(seven);
        U256 y2_mont    = fp_add(r3_mont, seven_mont);

        U256 y_mont;
        if (!fp_sqrt(y2_mont, y_mont)) {
            it.status = SECP256K1_ERR_NO_SQRT;
            continue;
        }
        // pick parity in stage_recover_R
        it.R_pt.x = r_p_mont;
        it.R_pt.y = y_mont;
        it.R_pt.infinity = false;
    }
}

// Stage 3: pick correct y by recovery id v.
inline void stage_recover_R(size_t n, EcrecoverWorkItem* items) {
    for (size_t i = 0; i < n; ++i) {
        EcrecoverWorkItem& it = items[i];
        if (it.status != SECP256K1_OK) continue;

        U256 y_normal = from_mont_p(it.R_pt.y);
        bool y_is_odd = (y_normal.limbs[0] & 1ULL) != 0;
        bool want_odd = (it.v_norm == 1);
        if (y_is_odd != want_odd) {
            U256 zero{};
            it.R_pt.y = fp_sub(zero, it.R_pt.y);
        }
    }
}

// Stage 4a: encode r in Fn-Montgomery (preparation for batch inversion).
inline void stage_prepare_r_inv(size_t n, EcrecoverWorkItem* items) {
    for (size_t i = 0; i < n; ++i) {
        EcrecoverWorkItem& it = items[i];
        if (it.status != SECP256K1_OK) {
            // Force a non-zero entry so batch_inv doesn't hit zero on this slot.
            it.r_n_mont = to_mont_n(U256{1, 0, 0, 0});
            continue;
        }
        it.r_n_mont = to_mont_n(it.r);
    }
}

// Stage 4b: BATCH INVERT r in Fn (one inversion total). This is where the
// algorithmic win comes from.
inline void stage_batch_invert_r(size_t n, EcrecoverWorkItem* items) {
    if (n == 0) return;
    std::vector<U256> in_v(n);
    std::vector<U256> out_v(n);
    for (size_t i = 0; i < n; ++i) in_v[i] = items[i].r_n_mont;

    // Single Fermat inversion + 2(n-1) Fn multiplications.
    batch_inv_fn(n, in_v.data(), out_v.data(), nullptr);

    for (size_t i = 0; i < n; ++i) items[i].r_inv_n_mont = out_v[i];
}

// Stage 4c: compute u1, u2 then Q = u1*G + u2*R. Uses windowed G table for u1*G.
inline void stage_scalar_mult_u1u2(size_t n, EcrecoverWorkItem* items) {
    const WindowedGTable& gt = windowed_g_table();
    for (size_t i = 0; i < n; ++i) {
        EcrecoverWorkItem& it = items[i];
        if (it.status != SECP256K1_OK) continue;

        U256 e_red = it.hash_e;
        if (U256::cmp(e_red, N) >= 0) {
            uint64_t bw;
            e_red = sub_256(e_red, N, bw);
        }
        U256 e_n_mont = to_mont_n(e_red);
        U256 s_n_mont = to_mont_n(it.s);

        // u1 = -(e * r_inv) mod n, in plain (non-Mont) form for mul-by-bits
        U256 u1_n_mont = fn_mul(e_n_mont, it.r_inv_n_mont);
        U256 u1 = from_mont_n(u1_n_mont);
        if (!u1.is_zero()) {
            uint64_t bw;
            u1 = sub_256(N, u1, bw);
        }
        U256 u2 = from_mont_n(fn_mul(s_n_mont, it.r_inv_n_mont));

        JacobianPoint Q1 = scalar_mul_g_windowed(gt, u1);
        // For u2*R we use the existing variable-base scalar mult (no window
        // table for R; one is constructed per signature would dwarf the win).
        AffinePoint Rp = it.R_pt;
        JacobianPoint Q2 = jac_mul(u2, Rp);
        it.Q = jac_add(Q1, Q2);
    }
}

// Stage 5: convert Q from Jacobian to affine. We BATCH-INVERT the Z values.
inline void stage_jacobian_to_affine(size_t n, EcrecoverWorkItem* items) {
    if (n == 0) return;
    std::vector<U256> z_in(n);
    std::vector<U256> z_inv(n);
    std::vector<uint8_t> mask((n + 7) / 8, 0);

    for (size_t i = 0; i < n; ++i) {
        if (items[i].status != SECP256K1_OK || items[i].Q.infinity || items[i].Q.Z.is_zero()) {
            z_in[i] = U256{}; // forces zero_mask bit, output skipped
        } else {
            z_in[i] = items[i].Q.Z;
        }
    }
    batch_inv_fp(n, z_in.data(), z_inv.data(), mask.data());

    for (size_t i = 0; i < n; ++i) {
        EcrecoverWorkItem& it = items[i];
        if (it.status != SECP256K1_OK) continue;
        if (it.Q.infinity || it.Q.Z.is_zero()
            || (mask[i / 8] & (uint8_t)(1u << (i & 7)))) {
            it.status = SECP256K1_ERR_AT_INFINITY;
            it.Q_aff.x = U256{}; it.Q_aff.y = U256{}; it.Q_aff.infinity = true;
            continue;
        }
        U256 z_inv2 = fp_sqr(z_inv[i]);
        U256 z_inv3 = fp_mul(z_inv2, z_inv[i]);
        it.Q_aff.x = fp_mul(it.Q.X, z_inv2);
        it.Q_aff.y = fp_mul(it.Q.Y, z_inv3);
        it.Q_aff.infinity = false;
    }
}

// Stage 6: keccak(pubkey)[12:32] -> 20-byte address
// Stage 7: compose output (pubkey or address)
inline void stage_compose_output_pubkey(size_t n, const EcrecoverWorkItem* items,
                                        uint8_t* out_pk, uint8_t* out_st) {
    for (size_t i = 0; i < n; ++i) {
        const EcrecoverWorkItem& it = items[i];
        if (out_st) out_st[i] = (uint8_t)it.status;
        if (it.status != SECP256K1_OK) continue;
        U256 qx = from_mont_p(it.Q_aff.x);
        U256 qy = from_mont_p(it.Q_aff.y);
        qx.to_be32(out_pk + i * 64);
        qy.to_be32(out_pk + i * 64 + 32);
    }
}

inline void stage_compose_output_address(size_t n, const EcrecoverWorkItem* items,
                                         uint8_t* out_addr, uint8_t* out_st) {
    for (size_t i = 0; i < n; ++i) {
        const EcrecoverWorkItem& it = items[i];
        if (out_st) out_st[i] = (uint8_t)it.status;
        if (it.status != SECP256K1_OK) continue;
        uint8_t pubkey[64];
        U256 qx = from_mont_p(it.Q_aff.x);
        U256 qy = from_mont_p(it.Q_aff.y);
        qx.to_be32(pubkey);
        qy.to_be32(pubkey + 32);
        uint8_t hash[32];
        keccak256(pubkey, 64, hash);
        std::memcpy(out_addr + i * 20, hash + 12, 20);
    }
}

// Top-level batch ecrecover using all 7 stages. Returns SECP256K1_OK on
// well-formed arguments; per-tuple status in out_st.
//
// Layout:
//   hashes  : n*32 bytes (one 32-byte hash per signature)
//   sigs    : n*65 bytes (r||s||v per signature)
//   out_pk  : n*64 bytes (uncompressed pubkey X||Y per signature)
//   out_st  : n     bytes (per-signature status)
inline secp256k1_status ecrecover_batch_pipeline(
    size_t n,
    const uint8_t* hashes,
    const uint8_t* sigs,
    uint8_t* out_pk,
    uint8_t* out_st) {

    if (n == 0) return SECP256K1_OK;
    if (!hashes || !sigs || !out_pk || !out_st) return SECP256K1_ERR_NULL_ARG;

    std::vector<EcrecoverWorkItem> items(n);

    stage_parse_reject(n, hashes, sigs, items.data());
    stage_field_normalize(n, items.data());
    stage_recover_R(n, items.data());
    stage_prepare_r_inv(n, items.data());
    stage_batch_invert_r(n, items.data());
    stage_scalar_mult_u1u2(n, items.data());
    stage_jacobian_to_affine(n, items.data());
    stage_compose_output_pubkey(n, items.data(), out_pk, out_st);
    return SECP256K1_OK;
}

// Same pipeline, address-mode output (20 bytes per sig instead of 64).
inline secp256k1_status ecrecover_address_batch_pipeline(
    size_t n,
    const uint8_t* hashes,
    const uint8_t* sigs,
    uint8_t* out_addr,
    uint8_t* out_st) {

    if (n == 0) return SECP256K1_OK;
    if (!hashes || !sigs || !out_addr || !out_st) return SECP256K1_ERR_NULL_ARG;

    std::vector<EcrecoverWorkItem> items(n);

    stage_parse_reject(n, hashes, sigs, items.data());
    stage_field_normalize(n, items.data());
    stage_recover_R(n, items.data());
    stage_prepare_r_inv(n, items.data());
    stage_batch_invert_r(n, items.data());
    stage_scalar_mult_u1u2(n, items.data());
    stage_jacobian_to_affine(n, items.data());
    stage_compose_output_address(n, items.data(), out_addr, out_st);
    return SECP256K1_OK;
}

}  // namespace kinet::crypto::secp256k1

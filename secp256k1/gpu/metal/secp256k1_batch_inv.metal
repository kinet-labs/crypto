// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Montgomery batch inversion for secp256k1 base field (Fp) and scalar field
// (Fn). Mirrors crypto/secp256k1/cpp/batch_inv.hpp; output must be byte-equal.
//
// Algorithm: forward prefix product, single Fermat inversion of last prefix,
// backward sweep with running inverse (Knuth TAOCP vol 2). One workgroup of
// one thread for byte-determinism.
//
// Inputs: n elements of Fp (or Fn) in Montgomery form.
// Outputs: n elements; out[i] = in[i]^-1 (Mont form).
// Caller must ensure no zero entries (this kernel does NOT check).

#include <metal_stdlib>
using namespace metal;

// =============================================================================
// 256-bit field constants — matches secp256k1.metal exactly
// =============================================================================

struct uint256 { ulong limbs[4]; };

constant uint256 P_MOD = {{
    0xFFFFFFFEFFFFFC2FUL, 0xFFFFFFFFFFFFFFFFUL,
    0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL
}};
constant uint256 N_MOD = {{
    0xBFD25E8CD0364141UL, 0xBAAEDCE6AF48A03BUL,
    0xFFFFFFFFFFFFFFFEUL, 0xFFFFFFFFFFFFFFFFUL
}};
constant ulong P_INV = 0xD838091DD2253531UL;
constant ulong N_INV = 0x4B0DFF665588B13FUL;
constant uint256 R2_N = {{
    0x896CF21467D7D140UL, 0x741496C20E7CF878UL,
    0xE697F5E45BCD07C6UL, 0x9D671CD581C69BC5UL
}};
constant uint256 ONE_MONT_P = {{ 0x00000001000003D1UL, 0UL, 0UL, 0UL }};
constant ulong P_M2[4] = {
    0xFFFFFFFEFFFFFC2DUL, 0xFFFFFFFFFFFFFFFFUL,
    0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL
};
constant ulong N_M2[4] = {
    0xBFD25E8CD036413FUL, 0xBAAEDCE6AF48A03BUL,
    0xFFFFFFFFFFFFFFFEUL, 0xFFFFFFFFFFFFFFFFUL
};
constant uint256 ONE = {{1, 0, 0, 0}};

inline int u256_cmp(uint256 a, uint256 b) {
    for (int i = 3; i >= 0; --i) {
        if (a.limbs[i] < b.limbs[i]) return -1;
        if (a.limbs[i] > b.limbs[i]) return 1;
    }
    return 0;
}

inline void mul64(ulong a, ulong b, thread ulong &lo, thread ulong &hi) {
    ulong al = a & 0xFFFFFFFFUL, ah = a >> 32;
    ulong bl = b & 0xFFFFFFFFUL, bh = b >> 32;
    ulong ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    ulong mid = (ll >> 32) + (lh & 0xFFFFFFFFUL) + (hl & 0xFFFFFFFFUL);
    lo = (ll & 0xFFFFFFFFUL) | (mid << 32);
    hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}

inline ulong addc(ulong a, ulong b, ulong c, thread ulong &out) {
    ulong t = a + b;
    ulong c1 = (t < a) ? 1UL : 0UL;
    ulong t2 = t + c;
    ulong c2 = (t2 < t) ? 1UL : 0UL;
    out = t2;
    return c1 + c2;
}

inline ulong subb(ulong a, ulong b, ulong br, thread ulong &out) {
    ulong t = a - b;
    ulong b1 = (t > a) ? 1UL : 0UL;
    ulong t2 = t - br;
    ulong b2 = (t2 > t) ? 1UL : 0UL;
    out = t2;
    return b1 + b2;
}

inline uint256 sub_256(uint256 a, uint256 b, thread ulong &borrow) {
    uint256 r;
    ulong br = 0;
    for (int i = 0; i < 4; ++i) br = subb(a.limbs[i], b.limbs[i], br, r.limbs[i]);
    borrow = br;
    return r;
}

inline uint256 mont_mul(uint256 a, uint256 b, uint256 m, ulong m_inv) {
    ulong t[6];
    for (int i = 0; i < 6; ++i) t[i] = 0;
    for (int i = 0; i < 4; ++i) {
        ulong carry = 0;
        for (int j = 0; j < 4; ++j) {
            ulong lo, hi;
            mul64(a.limbs[j], b.limbs[i], lo, hi);
            ulong c1 = addc(t[j], lo, carry, t[j]);
            carry = hi + c1;
        }
        ulong c1 = addc(t[4], carry, 0, t[4]);
        t[5] += c1;
        ulong u = t[0] * m_inv;
        carry = 0;
        for (int j = 0; j < 4; ++j) {
            ulong lo, hi;
            mul64(u, m.limbs[j], lo, hi);
            ulong c2 = addc(t[j], lo, carry, t[j]);
            carry = hi + c2;
        }
        ulong c2 = addc(t[4], carry, 0, t[4]);
        t[5] += c2;
        for (int j = 0; j < 5; ++j) t[j] = t[j + 1];
        t[5] = 0;
    }
    uint256 r = {{ t[0], t[1], t[2], t[3] }};
    if (t[4] != 0 || u256_cmp(r, m) >= 0) {
        ulong bw;
        r = sub_256(r, m, bw);
    }
    return r;
}

inline uint256 fp_mul(uint256 a, uint256 b) { return mont_mul(a, b, P_MOD, P_INV); }
inline uint256 fn_mul(uint256 a, uint256 b) { return mont_mul(a, b, N_MOD, N_INV); }
inline uint256 fp_sqr(uint256 a) { return mont_mul(a, a, P_MOD, P_INV); }
inline uint256 fn_sqr(uint256 a) { return mont_mul(a, a, N_MOD, N_INV); }

inline uint256 fp_pow(uint256 a, constant ulong* exp4) {
    uint256 result = ONE_MONT_P;
    uint256 base = a;
    for (int limb = 0; limb < 4; ++limb) {
        ulong w = exp4[limb];
        for (int bit = 0; bit < 64; ++bit) {
            if ((w >> bit) & 1) result = fp_mul(result, base);
            base = fp_sqr(base);
        }
    }
    return result;
}
inline uint256 fp_inv(uint256 a) { return fp_pow(a, P_M2); }

inline uint256 fn_pow(uint256 a, constant ulong* exp4) {
    uint256 result = mont_mul(ONE, R2_N, N_MOD, N_INV);
    uint256 base = a;
    for (int limb = 0; limb < 4; ++limb) {
        ulong w = exp4[limb];
        for (int bit = 0; bit < 64; ++bit) {
            if ((w >> bit) & 1) result = fn_mul(result, base);
            base = fn_sqr(base);
        }
    }
    return result;
}
inline uint256 fn_inv(uint256 a) { return fn_pow(a, N_M2); }

// =============================================================================
// Batch inversion kernels.
// One workgroup of 1 thread; the kernel walks the array sequentially. This
// preserves byte-equal output across CPU and Metal.
// =============================================================================

kernel void secp256k1_batch_inv_fp(
    device const uint256* in   [[buffer(0)]],
    device       uint256* out  [[buffer(1)]],
    constant uint& n           [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid != 0) return;
    if (n == 0) return;

    // Forward sweep: prefix products into out[].
    out[0] = in[0];
    for (uint i = 1; i < n; ++i) {
        out[i] = fp_mul(out[i - 1], in[i]);
    }
    // Single Fermat inversion of the last prefix.
    uint256 inv = fp_inv(out[n - 1]);
    // Backward sweep.
    for (uint k = n; k > 1; --k) {
        uint i = k - 1;
        uint256 t = fp_mul(inv, out[i - 1]);
        inv = fp_mul(inv, in[i]);
        out[i] = t;
    }
    out[0] = inv;
}

kernel void secp256k1_batch_inv_fn(
    device const uint256* in   [[buffer(0)]],
    device       uint256* out  [[buffer(1)]],
    constant uint& n           [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid != 0) return;
    if (n == 0) return;
    out[0] = in[0];
    for (uint i = 1; i < n; ++i) {
        out[i] = fn_mul(out[i - 1], in[i]);
    }
    uint256 inv = fn_inv(out[n - 1]);
    for (uint k = n; k > 1; --k) {
        uint i = k - 1;
        uint256 t = fn_mul(inv, out[i - 1]);
        inv = fn_mul(inv, in[i]);
        out[i] = t;
    }
    out[0] = inv;
}

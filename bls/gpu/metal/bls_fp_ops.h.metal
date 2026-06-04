// Shared Fp arithmetic primitives for BLS12-381 tower extensions.
// Included by bls_fp2.metal, bls_fp6.metal, bls_fp12.metal.
//
// All Fp values are stored in Montgomery form, 6 x 64-bit little-endian limbs,
// matching blst's `vec384` / `blst_fp` exactly so a memcpy round-trips.
//
// p   = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
// R   = 2^384 mod p
// p0  = -p^(-1) mod 2^64 = 0x89f3fffcfffcfffd  (matches blst src/consts.c)

#ifndef BLS_FP_OPS_H_METAL
#define BLS_FP_OPS_H_METAL

#include <metal_stdlib>
using namespace metal;

struct uint384 { ulong limbs[6]; };

constant uint384 BLS_P = {{
    0xB9FEFFFFFFFFAAABUL, 0x1EABFFFEB153FFFFUL, 0x6730D2A0F6B0F624UL,
    0x64774B84F38512BFUL, 0x4B1BA7B6434BACD7UL, 0x1A0111EA397FE69AUL
}};

constant uint384 BLS_R2 = {{
    0xF4DF1F341C341746UL, 0x0A76E6A609D104F1UL, 0x8DE5476C4C95B6D5UL,
    0x67EB88A9939D83C0UL, 0x9A793E85B519952DUL, 0x11988FE592CAE3AAUL
}};

constant uint384 BLS_R = {{
    0x760900000002FFFDUL, 0xEBF4000BC40C0002UL, 0x5F48985753C758BAUL,
    0x77CE585370525745UL, 0x5C071A97A256EC6DUL, 0x15F65EC3FA80E493UL
}};

constant ulong BLS_P_INV = 0x89F3FFFCFFFCFFFDUL;
constant uint384 ZERO384 = {{0,0,0,0,0,0}};

inline int u384_cmp(uint384 a, uint384 b) {
    for (int i = 5; i >= 0; i--) {
        if (a.limbs[i] < b.limbs[i]) return -1;
        if (a.limbs[i] > b.limbs[i]) return 1;
    }
    return 0;
}

inline bool u384_is_zero(uint384 a) {
    return (a.limbs[0]|a.limbs[1]|a.limbs[2]|a.limbs[3]|a.limbs[4]|a.limbs[5]) == 0;
}

inline uint384 u384_add(uint384 a, uint384 b, thread ulong& carry) {
    uint384 r; ulong c = 0;
    for (int i = 0; i < 6; i++) {
        ulong s1 = a.limbs[i] + c;
        ulong c1 = (s1 < a.limbs[i]) ? 1UL : 0UL;
        ulong s2 = s1 + b.limbs[i];
        ulong c2 = (s2 < s1) ? 1UL : 0UL;
        r.limbs[i] = s2;
        c = c1 + c2;
    }
    carry = c;
    return r;
}

inline uint384 u384_sub(uint384 a, uint384 b, thread ulong& borrow) {
    uint384 r; ulong bw = 0;
    for (int i = 0; i < 6; i++) {
        ulong d1 = a.limbs[i] - bw;
        ulong b1 = (d1 > a.limbs[i]) ? 1UL : 0UL;
        ulong d2 = d1 - b.limbs[i];
        ulong b2 = (d2 > d1) ? 1UL : 0UL;
        r.limbs[i] = d2;
        bw = b1 + b2;
    }
    borrow = bw;
    return r;
}

// 64x64 -> 128 (lo, hi) — Metal lacks native uint128.
inline void mul64(ulong a, ulong b, thread ulong& lo, thread ulong& hi) {
    ulong al = a & 0xFFFFFFFFUL, ah = a >> 32;
    ulong bl = b & 0xFFFFFFFFUL, bh = b >> 32;
    ulong ll = al*bl, lh = al*bh, hl = ah*bl, hh = ah*bh;
    ulong mid = lh + (ll >> 32);
    ulong mid2 = mid + hl;
    if (mid2 < mid) hh += (1UL << 32);
    lo = (mid2 << 32) | (ll & 0xFFFFFFFFUL);
    hi = hh + (mid2 >> 32);
}

// CIOS Montgomery reduction of 768-bit t  ->  t * R^(-1) mod p.
inline uint384 mont_reduce_384(ulong t[12]) {
    ulong a[13];
    for (int i = 0; i < 12; i++) a[i] = t[i];
    a[12] = 0;
    for (int i = 0; i < 6; i++) {
        ulong u = a[i] * BLS_P_INV;
        ulong carry = 0;
        for (int j = 0; j < 6; j++) {
            ulong lo, hi; mul64(u, BLS_P.limbs[j], lo, hi);
            ulong s = lo + carry; if (s < lo) hi++;
            lo = s;
            s = a[i+j] + lo; if (s < a[i+j]) hi++;
            a[i+j] = s;
            carry = hi;
        }
        for (int j = 6; i+j <= 12; j++) {
            ulong s = a[i+j] + carry;
            carry = (s < a[i+j]) ? 1UL : 0UL;
            a[i+j] = s;
            if (carry == 0) break;
        }
    }
    uint384 r;
    r.limbs[0]=a[6]; r.limbs[1]=a[7]; r.limbs[2]=a[8];
    r.limbs[3]=a[9]; r.limbs[4]=a[10]; r.limbs[5]=a[11];
    if (a[12] || u384_cmp(r, BLS_P) >= 0) {
        ulong bw; r = u384_sub(r, BLS_P, bw);
    }
    return r;
}

inline uint384 fp_mul(uint384 a, uint384 b) {
    ulong t[12] = {};
    for (int i = 0; i < 6; i++) {
        ulong carry = 0;
        for (int j = 0; j < 6; j++) {
            ulong lo, hi; mul64(a.limbs[i], b.limbs[j], lo, hi);
            ulong s = lo + carry; if (s < lo) hi++;
            lo = s;
            s = t[i+j] + lo; if (s < t[i+j]) hi++;
            t[i+j] = s;
            carry = hi;
        }
        for (int j = 6; i+j < 12; j++) {
            ulong s = t[i+j] + carry;
            carry = (s < t[i+j]) ? 1UL : 0UL;
            t[i+j] = s;
            if (carry == 0) break;
        }
    }
    return mont_reduce_384(t);
}

inline uint384 fp_sqr(uint384 a) { return fp_mul(a, a); }

inline uint384 fp_add(uint384 a, uint384 b) {
    ulong c; uint384 r = u384_add(a, b, c);
    if (c || u384_cmp(r, BLS_P) >= 0) {
        ulong bw; r = u384_sub(r, BLS_P, bw);
    }
    return r;
}

inline uint384 fp_sub(uint384 a, uint384 b) {
    ulong bw; uint384 r = u384_sub(a, b, bw);
    if (bw) { ulong c; r = u384_add(r, BLS_P, c); }
    return r;
}

inline uint384 fp_neg(uint384 a) {
    if (u384_is_zero(a)) return a;
    ulong bw; return u384_sub(BLS_P, a, bw);
}

// Fermat inversion: a^(p-2) mod p. Same modular inverse as blst's recip-addchain;
// produces identical Montgomery output bytes.
//
// Left-to-right binary square-and-multiply over the 381-bit exponent (p-2).
// Iterates from MSB to LSB; squares result every step, multiplies in `a` when
// the current bit is set. Skip leading zero bits to keep `result` at 1 until
// the first set bit (avoids unnecessary squarings before initialization).
inline uint384 fp_inv(uint384 a) {
    uint384 exp = BLS_P;          // exp = p
    // exp -= 2  on the bottom limb (low limb is well above 2)
    exp.limbs[0] -= 2;

    uint384 result = BLS_R;       // 1 in Montgomery form
    bool started = false;
    for (int i = 5; i >= 0; i--) {
        for (int bit = 63; bit >= 0; bit--) {
            if (started) result = fp_sqr(result);
            if ((exp.limbs[i] >> bit) & 1) {
                result = started ? fp_mul(result, a) : a;
                started = true;
            }
        }
    }
    return result;
}

#endif // BLS_FP_OPS_H_METAL

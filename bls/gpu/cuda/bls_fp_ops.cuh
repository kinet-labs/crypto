// CUDA port of bls_fp_ops.h.metal — byte-equal Fp arithmetic for BLS12-381.
//
// All Fp values are stored in Montgomery form, 6 x 64-bit little-endian limbs,
// matching blst's vec384 / blst_fp exactly. Algorithms are 1:1 translations of
// the Metal reference (bls_fp_ops.h.metal) which is itself byte-equal to blst.
//
// Compile-time switch via __CUDA_ARCH__: when not compiled with nvcc, the
// __device__ annotation degrades to nothing so the header is portable for
// stand-in builds (the actual kernels of course only live in nvcc objects).

#ifndef BLS_FP_OPS_CUH
#define BLS_FP_OPS_CUH

#include <cstdint>

#ifndef __CUDACC__
#define __device__
#define __host__
#define __forceinline__ inline
#endif

struct uint384 { uint64_t limbs[6]; };

__device__ __forceinline__ static const uint384 BLS_P_dev() {
    uint384 r = {{
        0xB9FEFFFFFFFFAAABULL, 0x1EABFFFEB153FFFFULL, 0x6730D2A0F6B0F624ULL,
        0x64774B84F38512BFULL, 0x4B1BA7B6434BACD7ULL, 0x1A0111EA397FE69AULL
    }}; return r;
}
__device__ __forceinline__ static const uint384 BLS_R_dev() {
    uint384 r = {{
        0x760900000002FFFDULL, 0xEBF4000BC40C0002ULL, 0x5F48985753C758BAULL,
        0x77CE585370525745ULL, 0x5C071A97A256EC6DULL, 0x15F65EC3FA80E493ULL
    }}; return r;
}
__device__ __forceinline__ static const uint384 BLS_R2_dev() {
    uint384 r = {{
        0xF4DF1F341C341746ULL, 0x0A76E6A609D104F1ULL, 0x8DE5476C4C95B6D5ULL,
        0x67EB88A9939D83C0ULL, 0x9A793E85B519952DULL, 0x11988FE592CAE3AAULL
    }}; return r;
}
__device__ __forceinline__ static const uint384 ZERO384_dev() {
    uint384 r = {{0,0,0,0,0,0}}; return r;
}
__device__ __forceinline__ static uint64_t BLS_P_INV_dev() {
    return 0x89F3FFFCFFFCFFFDULL;
}

__device__ __forceinline__ int u384_cmp(uint384 a, uint384 b) {
    for (int i = 5; i >= 0; i--) {
        if (a.limbs[i] < b.limbs[i]) return -1;
        if (a.limbs[i] > b.limbs[i]) return 1;
    }
    return 0;
}

__device__ __forceinline__ bool u384_is_zero(uint384 a) {
    return (a.limbs[0]|a.limbs[1]|a.limbs[2]|a.limbs[3]|a.limbs[4]|a.limbs[5]) == 0;
}

__device__ __forceinline__ uint384 u384_add(uint384 a, uint384 b, uint64_t& carry) {
    uint384 r; uint64_t c = 0;
    for (int i = 0; i < 6; i++) {
        uint64_t s1 = a.limbs[i] + c;
        uint64_t c1 = (s1 < a.limbs[i]) ? 1ULL : 0ULL;
        uint64_t s2 = s1 + b.limbs[i];
        uint64_t c2 = (s2 < s1) ? 1ULL : 0ULL;
        r.limbs[i] = s2;
        c = c1 + c2;
    }
    carry = c;
    return r;
}

__device__ __forceinline__ uint384 u384_sub(uint384 a, uint384 b, uint64_t& borrow) {
    uint384 r; uint64_t bw = 0;
    for (int i = 0; i < 6; i++) {
        uint64_t d1 = a.limbs[i] - bw;
        uint64_t b1 = (d1 > a.limbs[i]) ? 1ULL : 0ULL;
        uint64_t d2 = d1 - b.limbs[i];
        uint64_t b2 = (d2 > d1) ? 1ULL : 0ULL;
        r.limbs[i] = d2;
        bw = b1 + b2;
    }
    borrow = bw;
    return r;
}

// 64x64 -> 128 (lo, hi). On CUDA we have native __umul64hi.
__device__ __forceinline__ void mul64(uint64_t a, uint64_t b, uint64_t& lo, uint64_t& hi) {
#ifdef __CUDA_ARCH__
    lo = a * b;
    hi = __umul64hi(a, b);
#else
    uint64_t al = a & 0xFFFFFFFFULL, ah = a >> 32;
    uint64_t bl = b & 0xFFFFFFFFULL, bh = b >> 32;
    uint64_t ll = al*bl, lh = al*bh, hl = ah*bl, hh = ah*bh;
    uint64_t mid = lh + (ll >> 32);
    uint64_t mid2 = mid + hl;
    if (mid2 < mid) hh += (1ULL << 32);
    lo = (mid2 << 32) | (ll & 0xFFFFFFFFULL);
    hi = hh + (mid2 >> 32);
#endif
}

// CIOS Montgomery reduction of 768-bit t  ->  t * R^(-1) mod p.
__device__ __forceinline__ uint384 mont_reduce_384(uint64_t t[12]) {
    uint64_t a[13];
    for (int i = 0; i < 12; i++) a[i] = t[i];
    a[12] = 0;
    const uint384 P = BLS_P_dev();
    const uint64_t P_INV = BLS_P_INV_dev();
    for (int i = 0; i < 6; i++) {
        uint64_t u = a[i] * P_INV;
        uint64_t carry = 0;
        for (int j = 0; j < 6; j++) {
            uint64_t lo, hi; mul64(u, P.limbs[j], lo, hi);
            uint64_t s = lo + carry; if (s < lo) hi++;
            lo = s;
            s = a[i+j] + lo; if (s < a[i+j]) hi++;
            a[i+j] = s;
            carry = hi;
        }
        for (int j = 6; i+j <= 12; j++) {
            uint64_t s = a[i+j] + carry;
            carry = (s < a[i+j]) ? 1ULL : 0ULL;
            a[i+j] = s;
            if (carry == 0) break;
        }
    }
    uint384 r;
    r.limbs[0]=a[6]; r.limbs[1]=a[7]; r.limbs[2]=a[8];
    r.limbs[3]=a[9]; r.limbs[4]=a[10]; r.limbs[5]=a[11];
    if (a[12] || u384_cmp(r, P) >= 0) {
        uint64_t bw; r = u384_sub(r, P, bw);
    }
    return r;
}

__device__ __forceinline__ uint384 fp_mul(uint384 a, uint384 b) {
    uint64_t t[12] = {};
    for (int i = 0; i < 6; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 6; j++) {
            uint64_t lo, hi; mul64(a.limbs[i], b.limbs[j], lo, hi);
            uint64_t s = lo + carry; if (s < lo) hi++;
            lo = s;
            s = t[i+j] + lo; if (s < t[i+j]) hi++;
            t[i+j] = s;
            carry = hi;
        }
        for (int j = 6; i+j < 12; j++) {
            uint64_t s = t[i+j] + carry;
            carry = (s < t[i+j]) ? 1ULL : 0ULL;
            t[i+j] = s;
            if (carry == 0) break;
        }
    }
    return mont_reduce_384(t);
}

__device__ __forceinline__ uint384 fp_sqr(uint384 a) { return fp_mul(a, a); }

__device__ __forceinline__ uint384 fp_add(uint384 a, uint384 b) {
    uint64_t c; uint384 r = u384_add(a, b, c);
    const uint384 P = BLS_P_dev();
    if (c || u384_cmp(r, P) >= 0) {
        uint64_t bw; r = u384_sub(r, P, bw);
    }
    return r;
}

__device__ __forceinline__ uint384 fp_sub(uint384 a, uint384 b) {
    uint64_t bw; uint384 r = u384_sub(a, b, bw);
    if (bw) { uint64_t c; r = u384_add(r, BLS_P_dev(), c); }
    return r;
}

__device__ __forceinline__ uint384 fp_neg(uint384 a) {
    if (u384_is_zero(a)) return a;
    uint64_t bw; return u384_sub(BLS_P_dev(), a, bw);
}

// Fermat inversion. Same MSB->LSB binary square-and-multiply as Metal.
__device__ __forceinline__ uint384 fp_inv(uint384 a) {
    uint384 exp = BLS_P_dev();
    exp.limbs[0] -= 2;

    uint384 result = BLS_R_dev();
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

#endif // BLS_FP_OPS_CUH

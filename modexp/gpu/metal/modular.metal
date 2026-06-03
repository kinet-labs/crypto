// Modular Arithmetic - High-Performance Metal Implementation
// Montgomery and Barrett reduction for finite field operations.

#include <metal_stdlib>
using namespace metal;

// ============================================================================
// 64-bit Unsigned Integer (emulated)
// ============================================================================

struct U64 {
    uint lo;
    uint hi;
};

inline U64 u64_from(ulong v) {
    return {uint(v & 0xFFFFFFFFu), uint(v >> 32)};
}

inline ulong u64_to(U64 v) {
    return ulong(v.lo) | (ulong(v.hi) << 32);
}

inline U64 u64_zero() { return {0u, 0u}; }
inline U64 u64_one() { return {1u, 0u}; }

inline bool u64_eq(U64 a, U64 b) {
    return a.lo == b.lo && a.hi == b.hi;
}

inline bool u64_lt(U64 a, U64 b) {
    if (a.hi < b.hi) return true;
    if (a.hi > b.hi) return false;
    return a.lo < b.lo;
}

inline bool u64_gte(U64 a, U64 b) {
    return !u64_lt(a, b);
}

inline U64 u64_add(U64 a, U64 b) {
    uint lo = a.lo + b.lo;
    uint carry = (lo < a.lo) ? 1u : 0u;
    uint hi = a.hi + b.hi + carry;
    return {lo, hi};
}

inline U64 u64_sub(U64 a, U64 b) {
    uint borrow = (a.lo < b.lo) ? 1u : 0u;
    uint lo = a.lo - b.lo;
    uint hi = a.hi - b.hi - borrow;
    return {lo, hi};
}

// 32x32 -> 64 bit multiplication
inline U64 mul32_to_64(uint a, uint b) {
    uint a_lo = a & 0xFFFFu;
    uint a_hi = a >> 16u;
    uint b_lo = b & 0xFFFFu;
    uint b_hi = b >> 16u;

    uint p0 = a_lo * b_lo;
    uint p1 = a_lo * b_hi;
    uint p2 = a_hi * b_lo;
    uint p3 = a_hi * b_hi;

    uint mid = p1 + p2;
    uint mid_carry = (mid < p1) ? 0x10000u : 0u;

    uint lo = p0 + (mid << 16u);
    uint carry = (lo < p0) ? 1u : 0u;
    uint hi = p3 + (mid >> 16u) + mid_carry + carry;

    return {lo, hi};
}

// 64x64 -> 128 bit multiplication (returns low 64 bits and high 64 bits)
inline void mul64_to_128(U64 a, U64 b, thread U64& lo, thread U64& hi) {
    U64 p0 = mul32_to_64(a.lo, b.lo);
    U64 p1 = mul32_to_64(a.lo, b.hi);
    U64 p2 = mul32_to_64(a.hi, b.lo);
    U64 p3 = mul32_to_64(a.hi, b.hi);

    // lo = p0.lo, carry from p0.hi + p1.lo + p2.lo
    lo.lo = p0.lo;

    uint sum1 = p0.hi + p1.lo;
    uint c1 = (sum1 < p0.hi) ? 1u : 0u;
    uint sum2 = sum1 + p2.lo;
    uint c2 = (sum2 < sum1) ? 1u : 0u;
    lo.hi = sum2;

    // hi = p3 + p1.hi + p2.hi + carries
    uint carry_sum = c1 + c2 + p1.hi + p2.hi;
    hi = u64_add(p3, {carry_sum, 0u});
}

// ============================================================================
// Modular Arithmetic
// ============================================================================

// Modular addition: (a + b) mod q
inline U64 mod_add(U64 a, U64 b, U64 q) {
    U64 sum = u64_add(a, b);
    // Check for overflow or sum >= q
    bool overflow = (sum.hi < a.hi) || (sum.hi == a.hi && sum.lo < a.lo);
    if (overflow || u64_gte(sum, q)) {
        sum = u64_sub(sum, q);
    }
    return sum;
}

// Modular subtraction: (a - b) mod q
inline U64 mod_sub(U64 a, U64 b, U64 q) {
    if (u64_lt(a, b)) {
        return u64_sub(u64_add(a, q), b);
    }
    return u64_sub(a, b);
}

// Modular negation: -a mod q
inline U64 mod_neg(U64 a, U64 q) {
    if (u64_eq(a, u64_zero())) {
        return u64_zero();
    }
    return u64_sub(q, a);
}

// Barrett reduction for 128-bit product
inline U64 barrett_reduce_wide(U64 lo, U64 hi, U64 q, U64 mu) {
    // Approximate quotient: q_hat = (hi * mu) >> 64
    U64 q_lo, q_hi;
    mul64_to_128(hi, mu, q_lo, q_hi);

    // r = (lo, hi) - q_hat * q
    U64 prod_lo, prod_hi;
    mul64_to_128(q_hi, q, prod_lo, prod_hi);

    U64 r = u64_sub(lo, prod_lo);

    // Correction steps
    while (u64_gte(r, q)) {
        r = u64_sub(r, q);
    }

    return r;
}

// Modular multiplication using Barrett
inline U64 mod_mul(U64 a, U64 b, U64 q, U64 mu) {
    U64 lo, hi;
    mul64_to_128(a, b, lo, hi);
    return barrett_reduce_wide(lo, hi, q, mu);
}

// Montgomery reduction: compute aR^-1 mod q
inline U64 mont_reduce(U64 lo, U64 hi, U64 q, U64 m0_inv) {
    // m = lo * m0_inv (mod 2^64)
    U64 m_lo, m_hi;
    mul64_to_128(lo, m0_inv, m_lo, m_hi);

    // t = (lo + m*q) >> 64
    U64 prod_lo, prod_hi;
    mul64_to_128(m_lo, q, prod_lo, prod_hi);

    // Add lo + prod and take high part
    U64 sum = u64_add(lo, prod_lo);
    uint carry = u64_lt(sum, lo) ? 1u : 0u;

    U64 result = u64_add(hi, prod_hi);
    result = u64_add(result, {carry, 0u});

    // Conditional subtraction
    if (u64_gte(result, q)) {
        result = u64_sub(result, q);
    }

    return result;
}

// Montgomery multiplication
inline U64 mont_mul(U64 a, U64 b, U64 q, U64 m0_inv) {
    U64 lo, hi;
    mul64_to_128(a, b, lo, hi);
    return mont_reduce(lo, hi, q, m0_inv);
}

// Modular exponentiation (square-and-multiply)
inline U64 mod_pow(U64 base, U64 exp, U64 q, U64 mu) {
    U64 result = u64_one();
    U64 b = base;

    // Process low 32 bits
    uint e = exp.lo;
    while (e > 0) {
        if (e & 1u) {
            result = mod_mul(result, b, q, mu);
        }
        b = mod_mul(b, b, q, mu);
        e >>= 1u;
    }

    // Process high 32 bits
    e = exp.hi;
    while (e > 0) {
        if (e & 1u) {
            result = mod_mul(result, b, q, mu);
        }
        b = mod_mul(b, b, q, mu);
        e >>= 1u;
    }

    return result;
}

// Modular inverse using Fermat's little theorem: a^(q-2) mod q
inline U64 mod_inv(U64 a, U64 q, U64 mu) {
    U64 exp = u64_sub(q, {2u, 0u});
    return mod_pow(a, exp, q, mu);
}

// ============================================================================
// Batch Kernels
// ============================================================================

kernel void batch_mod_add(
    device const U64* a [[buffer(0)]],
    device const U64* b [[buffer(1)]],
    device U64* c [[buffer(2)]],
    constant U64& q [[buffer(3)]],
    constant uint& n [[buffer(4)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= n) return;
    c[gid] = mod_add(a[gid], b[gid], q);
}

kernel void batch_mod_sub(
    device const U64* a [[buffer(0)]],
    device const U64* b [[buffer(1)]],
    device U64* c [[buffer(2)]],
    constant U64& q [[buffer(3)]],
    constant uint& n [[buffer(4)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= n) return;
    c[gid] = mod_sub(a[gid], b[gid], q);
}

kernel void batch_mod_mul(
    device const U64* a [[buffer(0)]],
    device const U64* b [[buffer(1)]],
    device U64* c [[buffer(2)]],
    constant U64& q [[buffer(3)]],
    constant U64& mu [[buffer(4)]],
    constant uint& n [[buffer(5)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= n) return;
    c[gid] = mod_mul(a[gid], b[gid], q, mu);
}

kernel void batch_mont_mul(
    device const U64* a [[buffer(0)]],
    device const U64* b [[buffer(1)]],
    device U64* c [[buffer(2)]],
    constant U64& q [[buffer(3)]],
    constant U64& m0_inv [[buffer(4)]],
    constant uint& n [[buffer(5)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= n) return;
    c[gid] = mont_mul(a[gid], b[gid], q, m0_inv);
}

kernel void batch_mod_pow(
    device const U64* bases [[buffer(0)]],
    device const U64* exps [[buffer(1)]],
    device U64* results [[buffer(2)]],
    constant U64& q [[buffer(3)]],
    constant U64& mu [[buffer(4)]],
    constant uint& n [[buffer(5)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= n) return;
    results[gid] = mod_pow(bases[gid], exps[gid], q, mu);
}

kernel void batch_mod_inv(
    device const U64* a [[buffer(0)]],
    device U64* a_inv [[buffer(1)]],
    constant U64& q [[buffer(2)]],
    constant U64& mu [[buffer(3)]],
    constant uint& n [[buffer(4)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= n) return;
    a_inv[gid] = mod_inv(a[gid], q, mu);
}

kernel void batch_to_mont(
    device const U64* a [[buffer(0)]],
    device U64* a_mont [[buffer(1)]],
    constant U64& q [[buffer(2)]],
    constant U64& r2 [[buffer(3)]],
    constant U64& m0_inv [[buffer(4)]],
    constant uint& n [[buffer(5)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= n) return;
    a_mont[gid] = mont_mul(a[gid], r2, q, m0_inv);
}

kernel void batch_from_mont(
    device const U64* a_mont [[buffer(0)]],
    device U64* a [[buffer(1)]],
    constant U64& q [[buffer(2)]],
    constant U64& m0_inv [[buffer(3)]],
    constant uint& n [[buffer(4)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= n) return;
    a[gid] = mont_mul(a_mont[gid], u64_one(), q, m0_inv);
}

// First-party CUDA kernel for batched Pedersen vector commitments over BN254
// G1.  Mechanically ported from pedersen/gpu/metal/pedersen.metal -- byte-equal
// outputs to the Metal kernel and the Go canonical at
// github.com/kinet-labs/crypto/pedersen.
//
// Computed quantity (M parallel commitments, each of size N):
//
//   C_m = sum_{i=0..N-1}  s[m][i] * G[i]   +   r[m] * H        for m = 0..M-1
//
// Two-stage pipeline (one cubin, two kernels):
//   1. pedersen_pointmul    M*(N+1) threads, one per (commitment, term)
//   2. pedersen_reduce_add  M       threads, one per commitment
//
// Wire format identical to Metal driver: gens (N+1)*64 BE, scalars M*N*32 BE,
// blindings M*32 BE, output M*64 BE.

#include <cstdint>

#ifndef __CUDACC__
// Allow this file to compile with a plain C++ compiler so callers that lack
// the CUDA toolkit still get a non-error "translation unit empty" object.
#define __device__
#define __global__
#endif

// =============================================================================
// BN254 base-field constants
// =============================================================================

__device__ static const uint64_t BN254_P0 = 0x3C208C16D87CFD47ULL;
__device__ static const uint64_t BN254_P1 = 0x97816A916871CA8DULL;
__device__ static const uint64_t BN254_P2 = 0xB85045B68181585DULL;
__device__ static const uint64_t BN254_P3 = 0x30644E72E131A029ULL;

__device__ static const uint64_t BN254_R_0 = 0xD35D438DC58F0D9DULL;
__device__ static const uint64_t BN254_R_1 = 0x0A78EB28F5C70B3DULL;
__device__ static const uint64_t BN254_R_2 = 0x666EA36F7879462CULL;
__device__ static const uint64_t BN254_R_3 = 0x0E0A77C19A07DF2FULL;

__device__ static const uint64_t BN254_R2_0 = 0xF32CFC5B538AFA89ULL;
__device__ static const uint64_t BN254_R2_1 = 0xB5E71911D44501FBULL;
__device__ static const uint64_t BN254_R2_2 = 0x47AB1EFF0A417FF6ULL;
__device__ static const uint64_t BN254_R2_3 = 0x06D89F71CAB8351FULL;

__device__ static const uint64_t BN254_INV = 0x87D20782E4866389ULL;

// =============================================================================
// 256-bit big integer helpers
// =============================================================================

struct U256 { uint64_t l[4]; };

__device__ static inline U256 u256_zero() {
    U256 x; x.l[0]=0; x.l[1]=0; x.l[2]=0; x.l[3]=0; return x;
}

__device__ static inline bool u256_is_zero(const U256& a) {
    return (a.l[0] | a.l[1] | a.l[2] | a.l[3]) == 0;
}

__device__ static inline int u256_cmp_p(const U256& a) {
    if (a.l[3] != BN254_P3) return a.l[3] > BN254_P3 ? 1 : -1;
    if (a.l[2] != BN254_P2) return a.l[2] > BN254_P2 ? 1 : -1;
    if (a.l[1] != BN254_P1) return a.l[1] > BN254_P1 ? 1 : -1;
    if (a.l[0] != BN254_P0) return a.l[0] > BN254_P0 ? 1 : -1;
    return 0;
}

__device__ static inline U256 fp_p() {
    U256 r; r.l[0]=BN254_P0; r.l[1]=BN254_P1; r.l[2]=BN254_P2; r.l[3]=BN254_P3;
    return r;
}

__device__ static inline U256 fp_csub_p(const U256& a) {
    if (u256_cmp_p(a) < 0) return a;
    U256 r;
    uint64_t borrow = 0;
    uint64_t pl[4] = { BN254_P0, BN254_P1, BN254_P2, BN254_P3 };
    for (int i = 0; i < 4; ++i) {
        uint64_t ai = a.l[i];
        uint64_t s  = ai - pl[i] - borrow;
        borrow = ((ai < pl[i] + borrow) || (pl[i] + borrow < pl[i])) ? 1 : 0;
        r.l[i] = s;
    }
    return r;
}

__device__ static inline U256 fp_add(const U256& a, const U256& b) {
    U256 r;
    uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t s = a.l[i] + b.l[i];
        uint64_t c1 = (s < a.l[i]) ? 1 : 0;
        uint64_t s2 = s + carry;
        uint64_t c2 = (s2 < s) ? 1 : 0;
        r.l[i] = s2;
        carry = c1 + c2;
    }
    return fp_csub_p(r);
}

__device__ static inline U256 fp_sub(const U256& a, const U256& b) {
    U256 r;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t bi = b.l[i];
        uint64_t s = a.l[i] - bi - borrow;
        borrow = ((a.l[i] < bi + borrow) || (bi + borrow < bi)) ? 1 : 0;
        r.l[i] = s;
    }
    if (borrow) {
        uint64_t carry = 0;
        uint64_t pl[4] = { BN254_P0, BN254_P1, BN254_P2, BN254_P3 };
        for (int i = 0; i < 4; ++i) {
            uint64_t s = r.l[i] + pl[i];
            uint64_t c1 = (s < r.l[i]) ? 1 : 0;
            uint64_t s2 = s + carry;
            uint64_t c2 = (s2 < s) ? 1 : 0;
            r.l[i] = s2;
            carry = c1 + c2;
        }
    }
    return r;
}

// =============================================================================
// 64x64->128 multiplication (CUDA: __umul64hi for the high half)
// =============================================================================

#ifdef __CUDACC__
__device__ static inline uint64_t mul_hi64(uint64_t a, uint64_t b) {
    return __umul64hi(a, b);
}
#else
__device__ static inline uint64_t mul_hi64(uint64_t a, uint64_t b) {
#if defined(__SIZEOF_INT128__)
    return (uint64_t)(((__uint128_t)a * (__uint128_t)b) >> 64);
#else
    uint64_t a_lo = (uint32_t)a, a_hi = a >> 32;
    uint64_t b_lo = (uint32_t)b, b_hi = b >> 32;
    uint64_t ll = a_lo * b_lo;
    uint64_t lh = a_lo * b_hi;
    uint64_t hl = a_hi * b_lo;
    uint64_t hh = a_hi * b_hi;
    uint64_t mid = (ll >> 32) + (uint32_t)lh + (uint32_t)hl;
    return hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
#endif
}
#endif

// =============================================================================
// Montgomery multiplication (CIOS, 4-limb specialized) -- byte-identical to Metal
// =============================================================================

__device__ static inline U256 fp_mont_mul(const U256& a, const U256& b) {
    uint64_t pl[4] = { BN254_P0, BN254_P1, BN254_P2, BN254_P3 };

    uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;
    uint64_t t5 = 0;

    for (int i = 0; i < 4; ++i) {
        uint64_t ai = a.l[i];

        // Step A: t += a[i] * b
        {
            uint64_t carry = 0;
            uint64_t lo, hi;
            // j=0
            lo = ai * b.l[0]; hi = mul_hi64(ai, b.l[0]);
            uint64_t s = t0 + lo;
            uint64_t c1 = (s < t0) ? 1ULL : 0ULL;
            t0 = s;
            carry = hi + c1;
            // j=1
            lo = ai * b.l[1]; hi = mul_hi64(ai, b.l[1]);
            s = t1 + lo;
            c1 = (s < t1) ? 1ULL : 0ULL;
            uint64_t s2 = s + carry;
            uint64_t c2 = (s2 < s) ? 1ULL : 0ULL;
            t1 = s2;
            carry = hi + c1 + c2;
            // j=2
            lo = ai * b.l[2]; hi = mul_hi64(ai, b.l[2]);
            s = t2 + lo;
            c1 = (s < t2) ? 1ULL : 0ULL;
            s2 = s + carry;
            c2 = (s2 < s) ? 1ULL : 0ULL;
            t2 = s2;
            carry = hi + c1 + c2;
            // j=3
            lo = ai * b.l[3]; hi = mul_hi64(ai, b.l[3]);
            s = t3 + lo;
            c1 = (s < t3) ? 1ULL : 0ULL;
            s2 = s + carry;
            c2 = (s2 < s) ? 1ULL : 0ULL;
            t3 = s2;
            carry = hi + c1 + c2;
            // propagate
            s = t4 + carry;
            c1 = (s < t4) ? 1ULL : 0ULL;
            t4 = s;
            t5 = t5 + c1;
        }

        // Step B: m = t0 * INV mod 2^64; t = t + m*p; shift down.
        uint64_t m = t0 * BN254_INV;
        {
            uint64_t carry = 0;
            uint64_t lo, hi;
            // j=0 (zeroes t0)
            lo = m * pl[0]; hi = mul_hi64(m, pl[0]);
            uint64_t s = t0 + lo;
            uint64_t c1 = (s < t0) ? 1ULL : 0ULL;
            carry = hi + c1;
            // j=1
            lo = m * pl[1]; hi = mul_hi64(m, pl[1]);
            s = t1 + lo;
            c1 = (s < t1) ? 1ULL : 0ULL;
            uint64_t s2 = s + carry;
            uint64_t c2 = (s2 < s) ? 1ULL : 0ULL;
            t1 = s2;
            carry = hi + c1 + c2;
            // j=2
            lo = m * pl[2]; hi = mul_hi64(m, pl[2]);
            s = t2 + lo;
            c1 = (s < t2) ? 1ULL : 0ULL;
            s2 = s + carry;
            c2 = (s2 < s) ? 1ULL : 0ULL;
            t2 = s2;
            carry = hi + c1 + c2;
            // j=3
            lo = m * pl[3]; hi = mul_hi64(m, pl[3]);
            s = t3 + lo;
            c1 = (s < t3) ? 1ULL : 0ULL;
            s2 = s + carry;
            c2 = (s2 < s) ? 1ULL : 0ULL;
            t3 = s2;
            carry = hi + c1 + c2;
            // propagate
            s = t4 + carry;
            c1 = (s < t4) ? 1ULL : 0ULL;
            t4 = s;
            t5 = t5 + c1;

            // shift down by one limb
            t0 = t1; t1 = t2; t2 = t3; t3 = t4; t4 = t5; t5 = 0;
        }
    }

    U256 r; r.l[0]=t0; r.l[1]=t1; r.l[2]=t2; r.l[3]=t3;
    if (t4 != 0) {
        U256 p = fp_p();
        r = fp_sub(r, p);
    }
    return fp_csub_p(r);
}

__device__ static inline U256 fp_mont_sqr(const U256& a) { return fp_mont_mul(a, a); }

__device__ static inline U256 fp_one_mont() {
    U256 r; r.l[0]=BN254_R_0; r.l[1]=BN254_R_1; r.l[2]=BN254_R_2; r.l[3]=BN254_R_3;
    return r;
}

__device__ static inline U256 fp_r2() {
    U256 r; r.l[0]=BN254_R2_0; r.l[1]=BN254_R2_1; r.l[2]=BN254_R2_2; r.l[3]=BN254_R2_3;
    return r;
}

__device__ static inline U256 fp_to_mont(const U256& x) { return fp_mont_mul(x, fp_r2()); }

__device__ static inline U256 fp_from_mont(const U256& x) {
    U256 one; one.l[0]=1; one.l[1]=0; one.l[2]=0; one.l[3]=0;
    return fp_mont_mul(x, one);
}

// Inversion via Fermat's little theorem (a^(p-2)).  Identical bit-loop to Metal.
__device__ static inline U256 fp_inv(const U256& a) {
    if (u256_is_zero(a)) return a;

    uint64_t exp[4] = { BN254_P0 - 2ULL, BN254_P1, BN254_P2, BN254_P3 };

    U256 result = fp_one_mont();
    U256 base = a;
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t e = exp[limb];
        for (int b = 0; b < 64; ++b) {
            if ((e >> b) & 1ULL) {
                result = fp_mont_mul(result, base);
            }
            base = fp_mont_sqr(base);
        }
    }
    return result;
}

// =============================================================================
// G1 in Jacobian coordinates (Montgomery form for X, Y, Z)
// =============================================================================

struct G1Jac { U256 X, Y, Z; };
struct G1Aff { U256 X, Y; bool inf; };

__device__ static inline G1Jac g1_zero() {
    G1Jac p;
    p.X = fp_one_mont();
    p.Y = fp_one_mont();
    p.Z = u256_zero();
    return p;
}

__device__ static inline bool g1_is_zero(const G1Jac& p) { return u256_is_zero(p.Z); }

__device__ static inline G1Jac g1_dbl(const G1Jac& p) {
    if (g1_is_zero(p)) return p;
    U256 A = fp_mont_sqr(p.X);
    U256 B = fp_mont_sqr(p.Y);
    U256 C = fp_mont_sqr(B);
    U256 t = fp_add(p.X, B);
    U256 t2 = fp_mont_sqr(t);
    U256 t3 = fp_sub(t2, A);
    U256 t4 = fp_sub(t3, C);
    U256 D = fp_add(t4, t4);
    U256 E = fp_add(fp_add(A, A), A);
    U256 F = fp_mont_sqr(E);
    G1Jac r;
    U256 twoD = fp_add(D, D);
    r.X = fp_sub(F, twoD);
    U256 D_minus_X = fp_sub(D, r.X);
    U256 EDX = fp_mont_mul(E, D_minus_X);
    U256 eightC = fp_add(C, C);
    eightC = fp_add(eightC, eightC);
    eightC = fp_add(eightC, eightC);
    r.Y = fp_sub(EDX, eightC);
    U256 YZ = fp_mont_mul(p.Y, p.Z);
    r.Z = fp_add(YZ, YZ);
    return r;
}

__device__ static inline G1Jac g1_add_mixed(const G1Jac& p, const U256& Qx, const U256& Qy) {
    if (g1_is_zero(p)) {
        G1Jac r;
        r.X = Qx; r.Y = Qy; r.Z = fp_one_mont();
        return r;
    }
    U256 Z1Z1 = fp_mont_sqr(p.Z);
    U256 U2 = fp_mont_mul(Qx, Z1Z1);
    U256 S2 = fp_mont_mul(Qy, fp_mont_mul(p.Z, Z1Z1));
    U256 H = fp_sub(U2, p.X);
    U256 r_v = fp_sub(S2, p.Y);
    if (u256_is_zero(H)) {
        if (u256_is_zero(r_v)) return g1_dbl(p);
        return g1_zero();
    }
    U256 HH = fp_mont_sqr(H);
    U256 I = fp_add(HH, HH);
    I = fp_add(I, I);
    U256 J = fp_mont_mul(H, I);
    U256 r_2 = fp_add(r_v, r_v);
    U256 V = fp_mont_mul(p.X, I);
    G1Jac out;
    U256 r_sq = fp_mont_sqr(r_2);
    U256 t1 = fp_sub(r_sq, J);
    U256 twoV = fp_add(V, V);
    out.X = fp_sub(t1, twoV);
    U256 V_minus_X3 = fp_sub(V, out.X);
    U256 r_VX = fp_mont_mul(r_2, V_minus_X3);
    U256 Y1J = fp_mont_mul(p.Y, J);
    U256 twoY1J = fp_add(Y1J, Y1J);
    out.Y = fp_sub(r_VX, twoY1J);
    out.Z = fp_mont_mul(p.Z, fp_add(H, H));
    return out;
}

__device__ static inline G1Jac g1_add(const G1Jac& p, const G1Jac& q) {
    if (g1_is_zero(p)) return q;
    if (g1_is_zero(q)) return p;
    U256 Z1Z1 = fp_mont_sqr(p.Z);
    U256 Z2Z2 = fp_mont_sqr(q.Z);
    U256 U1 = fp_mont_mul(p.X, Z2Z2);
    U256 U2 = fp_mont_mul(q.X, Z1Z1);
    U256 S1 = fp_mont_mul(fp_mont_mul(p.Y, q.Z), Z2Z2);
    U256 S2 = fp_mont_mul(fp_mont_mul(q.Y, p.Z), Z1Z1);
    U256 H = fp_sub(U2, U1);
    U256 r_v = fp_sub(S2, S1);
    if (u256_is_zero(H)) {
        if (u256_is_zero(r_v)) return g1_dbl(p);
        return g1_zero();
    }
    U256 r2 = fp_add(r_v, r_v);
    U256 HH = fp_mont_sqr(H);
    U256 I = fp_add(HH, HH);
    I = fp_add(I, I);
    U256 J = fp_mont_mul(H, I);
    U256 V = fp_mont_mul(U1, I);
    G1Jac out;
    U256 r_sq = fp_mont_sqr(r2);
    U256 t1 = fp_sub(r_sq, J);
    U256 twoV = fp_add(V, V);
    out.X = fp_sub(t1, twoV);
    U256 V_minus_X3 = fp_sub(V, out.X);
    U256 r_VX = fp_mont_mul(r2, V_minus_X3);
    U256 S1J = fp_mont_mul(S1, J);
    U256 twoS1J = fp_add(S1J, S1J);
    out.Y = fp_sub(r_VX, twoS1J);
    U256 Z1Z2 = fp_mont_mul(p.Z, q.Z);
    out.Z = fp_mont_mul(Z1Z2, fp_add(H, H));
    return out;
}

__device__ static inline G1Aff g1_to_affine(const G1Jac& p) {
    G1Aff r;
    if (g1_is_zero(p)) {
        r.X = u256_zero(); r.Y = u256_zero(); r.inf = true;
        return r;
    }
    U256 Zinv = fp_inv(p.Z);
    U256 Zinv2 = fp_mont_sqr(Zinv);
    U256 Zinv3 = fp_mont_mul(Zinv2, Zinv);
    r.X = fp_mont_mul(p.X, Zinv2);
    r.Y = fp_mont_mul(p.Y, Zinv3);
    r.inf = false;
    return r;
}

__device__ static inline G1Jac g1_scalar_mul_aff(const U256& Qx, const U256& Qy,
                                                  const uint64_t s[4]) {
    G1Jac acc = g1_zero();
    for (int li = 3; li >= 0; --li) {
        uint64_t limb = s[li];
        for (int bi = 63; bi >= 0; --bi) {
            acc = g1_dbl(acc);
            if ((limb >> bi) & 1ULL) {
                acc = g1_add_mixed(acc, Qx, Qy);
            }
        }
    }
    return acc;
}

// =============================================================================
// I/O helpers (raw 32-byte BE Fp <-> 4 LE limbs)
// =============================================================================

__device__ static inline U256 read_be32(const uint8_t* p) {
    U256 r;
    for (int limb = 0; limb < 4; ++limb) {
        const uint8_t* src = p + (3 - limb) * 8;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | (uint64_t)src[i];
        r.l[limb] = v;
    }
    return r;
}

__device__ static inline void write_be32(uint8_t* p, const U256& a) {
    for (int limb = 0; limb < 4; ++limb) {
        uint8_t* dst = p + (3 - limb) * 8;
        uint64_t v = a.l[limb];
        for (int i = 7; i >= 0; --i) {
            dst[i] = (uint8_t)(v & 0xFFu);
            v >>= 8;
        }
    }
}

// =============================================================================
// Kernel 1: pedersen_pointmul -- one thread per (m, i) scalar multiplication
// =============================================================================

struct PedersenDims { uint32_t M; uint32_t N; };

extern "C" __global__ void k_pedersen_pointmul(
    const uint8_t* __restrict__ gens_be,       // (N+1)*64 BE bytes
    const uint8_t* __restrict__ scalars_be,    // M*N*32 BE bytes
    const uint8_t* __restrict__ blindings_be,  // M*32 BE bytes
    uint64_t*       __restrict__ scratch,      // M*(N+1)*12 u64
    PedersenDims    dims) {
#ifdef __CUDACC__
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
#else
    uint32_t tid = 0;
#endif
    uint32_t M = dims.M;
    uint32_t N = dims.N;
    uint32_t total = M * (N + 1);
    if (tid >= total) return;

    uint32_t m = tid / (N + 1);
    uint32_t i = tid - m * (N + 1);

    U256 Qx_raw, Qy_raw, scalar_raw;
    if (i < N) {
        Qx_raw = read_be32(gens_be + i * 64);
        Qy_raw = read_be32(gens_be + i * 64 + 32);
        scalar_raw = read_be32(scalars_be + (m * N + i) * 32);
    } else {
        Qx_raw = read_be32(gens_be + N * 64);
        Qy_raw = read_be32(gens_be + N * 64 + 32);
        scalar_raw = read_be32(blindings_be + m * 32);
    }

    U256 Qx = fp_to_mont(Qx_raw);
    U256 Qy = fp_to_mont(Qy_raw);

    uint64_t s[4] = { scalar_raw.l[0], scalar_raw.l[1], scalar_raw.l[2], scalar_raw.l[3] };
    G1Jac result = g1_scalar_mul_aff(Qx, Qy, s);

    uint32_t base = tid * 12;
    for (int k = 0; k < 4; ++k) scratch[base + 0 + k] = result.X.l[k];
    for (int k = 0; k < 4; ++k) scratch[base + 4 + k] = result.Y.l[k];
    for (int k = 0; k < 4; ++k) scratch[base + 8 + k] = result.Z.l[k];
}

// =============================================================================
// Kernel 2: pedersen_reduce_add -- one thread per commitment
// =============================================================================

__device__ static inline G1Jac scratch_load(const uint64_t* scratch, uint32_t idx) {
    G1Jac r;
    uint32_t base = idx * 12;
    for (int k = 0; k < 4; ++k) r.X.l[k] = scratch[base + 0 + k];
    for (int k = 0; k < 4; ++k) r.Y.l[k] = scratch[base + 4 + k];
    for (int k = 0; k < 4; ++k) r.Z.l[k] = scratch[base + 8 + k];
    return r;
}

extern "C" __global__ void k_pedersen_reduce_add(
    const uint64_t* __restrict__ scratch,  // M*(N+1)*12 u64
    uint8_t*        __restrict__ out_be,   // M*64 BE bytes
    PedersenDims    dims) {
#ifdef __CUDACC__
    uint32_t m = blockIdx.x * blockDim.x + threadIdx.x;
#else
    uint32_t m = 0;
#endif
    uint32_t M = dims.M;
    uint32_t N = dims.N;
    if (m >= M) return;

    uint32_t base = m * (N + 1);
    G1Jac acc = g1_zero();
    for (uint32_t i = 0; i < N + 1; ++i) {
        G1Jac term = scratch_load(scratch, base + i);
        if (g1_is_zero(term)) continue;
        acc = g1_add(acc, term);
    }

    G1Aff aff = g1_to_affine(acc);
    if (aff.inf) {
        uint8_t* dst = out_be + m * 64;
        for (int b = 0; b < 64; ++b) dst[b] = 0;
        return;
    }
    U256 X_raw = fp_from_mont(aff.X);
    U256 Y_raw = fp_from_mont(aff.Y);
    write_be32(out_be + m * 64,        X_raw);
    write_be32(out_be + m * 64 + 32,   Y_raw);
}

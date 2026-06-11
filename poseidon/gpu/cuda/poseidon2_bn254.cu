// First-party CUDA kernel for Poseidon2-BN254 (canonical default permutation).
//
// Mechanical port of poseidon/gpu/metal/poseidon2_bn254.metal -- byte-for-byte
// equivalent to kinet::crypto::poseidon::hash2 in poseidon/cpp/poseidon.cpp
// (gnark-crypto v0.20.1 ecc/bn254/fr/poseidon2 with t=2, rF=6, rP=50, d=5).
//
// The round-key constant table is emitted by the same CPU body via
// dump_round_keys -> gen_gpu_constants -> poseidon2_bn254_rk.cuh, so there is
// exactly one source of truth for round constants across CPU, Metal, CUDA,
// and WGSL backends.
//
// Compile with nvcc compute_60+ on Linux/CUDA hosts. On hosts without nvcc
// (Apple, plain g++/clang++), the file compiles via a host-side polyfill that
// elides __device__/__global__/__host__ qualifiers and lets the kernel run
// on the CPU oracle path. The polyfill is exercised by the parity test;
// production GPU dispatch uses the real nvcc-compiled path.

#include <cstdint>
#include <cstring>

// Polyfill: when not building with nvcc, neutralize the device qualifiers.
#ifndef __CUDA_ARCH__
#  ifndef KINET_POSEIDON_CUDA_HOST_POLYFILL
#    define KINET_POSEIDON_CUDA_HOST_POLYFILL 1
#  endif
#endif

#if KINET_POSEIDON_CUDA_HOST_POLYFILL
#  define __device__
#  define __global__
#  define __host__
#  define __forceinline__ inline
#endif

#include "poseidon2_bn254_rk.cuh"  // POSEIDON2_RK[56][2][4]

// =============================================================================
// BN254 Fr modulus q (4x64 little-endian limbs).
//   q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
// Montgomery params: qInvNeg = -q^{-1} mod 2^64; rSquare = R^2 mod q.
// All values match poseidon/cpp/poseidon.cpp byte-for-byte.
// =============================================================================
__device__ static const unsigned long long Q0 = 0x43e1f593f0000001ULL;
__device__ static const unsigned long long Q1 = 0x2833e84879b97091ULL;
__device__ static const unsigned long long Q2 = 0xb85045b68181585dULL;
__device__ static const unsigned long long Q3 = 0x30644e72e131a029ULL;
__device__ static const unsigned long long Q_INV_NEG = 0xc2e1f593efffffffULL;

__device__ static const unsigned long long R_SQUARE_0 = 1997599621687373223ULL;
__device__ static const unsigned long long R_SQUARE_1 = 6052339484930628067ULL;
__device__ static const unsigned long long R_SQUARE_2 = 10108755138030829701ULL;
__device__ static const unsigned long long R_SQUARE_3 = 150537098327114917ULL;

// 256-bit field element in Montgomery form.
struct Fr {
    unsigned long long l0, l1, l2, l3;
};

// =============================================================================
// 64x64 -> 128 multiply. nvcc emits __umul64hi for the high half on the GPU;
// the host polyfill uses __int128 (or a portable fallback if unavailable).
// =============================================================================
__device__ __forceinline__ void mul64(unsigned long long a,
                                      unsigned long long b,
                                      unsigned long long &lo,
                                      unsigned long long &hi) {
#if defined(__CUDA_ARCH__)
    lo = a * b;
    hi = __umul64hi(a, b);
#elif defined(__SIZEOF_INT128__)
    unsigned __int128 t = (unsigned __int128)a * b;
    lo = (unsigned long long)t;
    hi = (unsigned long long)(t >> 64);
#else
    unsigned long long al = a & 0xffffffffULL, ah = a >> 32;
    unsigned long long bl = b & 0xffffffffULL, bh = b >> 32;
    unsigned long long ll = al * bl;
    unsigned long long lh = al * bh;
    unsigned long long hl = ah * bl;
    unsigned long long hh = ah * bh;
    unsigned long long mid =
        (ll >> 32) + (lh & 0xffffffffULL) + (hl & 0xffffffffULL);
    lo = (ll & 0xffffffffULL) | (mid << 32);
    hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
#endif
}

// adc/sbb: same carry-chain pattern as the CPU body.
__device__ __forceinline__ unsigned long long adc(unsigned long long a,
                                                  unsigned long long b,
                                                  unsigned long long &carry) {
    unsigned long long s = a + b;
    unsigned long long c1 = (s < a) ? 1ULL : 0ULL;
    unsigned long long s2 = s + carry;
    unsigned long long c2 = (s2 < s) ? 1ULL : 0ULL;
    carry = c1 + c2;
    return s2;
}

__device__ __forceinline__ unsigned long long sbb(unsigned long long a,
                                                  unsigned long long b,
                                                  unsigned long long &borrow) {
    unsigned long long d = a - b;
    unsigned long long b1 = (a < b) ? 1ULL : 0ULL;
    unsigned long long d2 = d - borrow;
    unsigned long long b2 = (d < borrow) ? 1ULL : 0ULL;
    borrow = b1 + b2;
    return d2;
}

__device__ __forceinline__ int cmp_q(const Fr &a) {
    if (a.l3 != Q3) return (a.l3 < Q3) ? -1 : 1;
    if (a.l2 != Q2) return (a.l2 < Q2) ? -1 : 1;
    if (a.l1 != Q1) return (a.l1 < Q1) ? -1 : 1;
    if (a.l0 != Q0) return (a.l0 < Q0) ? -1 : 1;
    return 0;
}

__device__ __forceinline__ void reduce_once(Fr &a) {
    if (cmp_q(a) >= 0) {
        unsigned long long br = 0;
        a.l0 = sbb(a.l0, Q0, br);
        a.l1 = sbb(a.l1, Q1, br);
        a.l2 = sbb(a.l2, Q2, br);
        a.l3 = sbb(a.l3, Q3, br);
    }
}

__device__ __forceinline__ Fr fr_add(const Fr &a, const Fr &b) {
    Fr c;
    unsigned long long cy = 0;
    c.l0 = adc(a.l0, b.l0, cy);
    c.l1 = adc(a.l1, b.l1, cy);
    c.l2 = adc(a.l2, b.l2, cy);
    c.l3 = adc(a.l3, b.l3, cy);
    if (cy != 0 || cmp_q(c) >= 0) {
        unsigned long long br = 0;
        c.l0 = sbb(c.l0, Q0, br);
        c.l1 = sbb(c.l1, Q1, br);
        c.l2 = sbb(c.l2, Q2, br);
        c.l3 = sbb(c.l3, Q3, br);
    }
    return c;
}

__device__ __forceinline__ Fr fr_double(const Fr &a) { return fr_add(a, a); }

// CIOS Montgomery multiplication. Identical algorithm to the CPU body.
__device__ __forceinline__ Fr fr_mul(const Fr &a, const Fr &b) {
    unsigned long long t[5] = {0, 0, 0, 0, 0};
    const unsigned long long al[4] = {a.l0, a.l1, a.l2, a.l3};
    const unsigned long long bl[4] = {b.l0, b.l1, b.l2, b.l3};
    const unsigned long long qq[4] = {Q0, Q1, Q2, Q3};

    for (int i = 0; i < 4; ++i) {
        unsigned long long cy = 0;
        for (int j = 0; j < 4; ++j) {
            unsigned long long lo, hi;
            mul64(al[j], bl[i], lo, hi);
            unsigned long long s = t[j] + lo;
            unsigned long long c1 = (s < t[j]) ? 1ULL : 0ULL;
            unsigned long long s2 = s + cy;
            unsigned long long c2 = (s2 < s) ? 1ULL : 0ULL;
            t[j] = s2;
            cy = hi + c1 + c2;
        }
        t[4] += cy;

        unsigned long long m = t[0] * Q_INV_NEG;

        cy = 0;
        for (int j = 0; j < 4; ++j) {
            unsigned long long lo, hi;
            mul64(m, qq[j], lo, hi);
            unsigned long long s = t[j] + lo;
            unsigned long long c1 = (s < t[j]) ? 1ULL : 0ULL;
            unsigned long long s2 = s + cy;
            unsigned long long c2 = (s2 < s) ? 1ULL : 0ULL;
            t[j] = s2;
            cy = hi + c1 + c2;
        }
        t[4] += cy;

        t[0] = t[1];
        t[1] = t[2];
        t[2] = t[3];
        t[3] = t[4];
        t[4] = 0;
    }
    Fr c;
    c.l0 = t[0]; c.l1 = t[1]; c.l2 = t[2]; c.l3 = t[3];
    reduce_once(c);
    return c;
}

__device__ __forceinline__ Fr fr_square(const Fr &a) { return fr_mul(a, a); }

// =============================================================================
// Poseidon2-BN254 default permutation (t=2, rF=6 split 3+3, rP=50, d=5).
// =============================================================================

__device__ __forceinline__ void sbox(Fr &x) {
    Fr x2 = fr_square(x);
    Fr x4 = fr_square(x2);
    x = fr_mul(x4, x);
}

__device__ __forceinline__ void mat_mul_external(Fr s[2]) {
    Fr tmp = fr_add(s[0], s[1]);
    s[0] = fr_add(s[0], tmp);
    s[1] = fr_add(s[1], tmp);
}

__device__ __forceinline__ void mat_mul_internal(Fr s[2]) {
    Fr sum = fr_add(s[0], s[1]);
    s[0] = fr_add(s[0], sum);
    Fr s1d = fr_double(s[1]);
    s[1] = fr_add(s1d, sum);
}

#define POSEIDON_FULL_HALF 3
#define POSEIDON_PARTIAL   50

__device__ __forceinline__ Fr load_rk(int round, int slot) {
    Fr r;
    r.l0 = POSEIDON2_RK[round][slot][0];
    r.l1 = POSEIDON2_RK[round][slot][1];
    r.l2 = POSEIDON2_RK[round][slot][2];
    r.l3 = POSEIDON2_RK[round][slot][3];
    return r;
}

__device__ __forceinline__ void permute(Fr s[2]) {
    mat_mul_external(s);
    for (int i = 0; i < POSEIDON_FULL_HALF; ++i) {
        Fr k0 = load_rk(i, 0);
        Fr k1 = load_rk(i, 1);
        s[0] = fr_add(s[0], k0);
        s[1] = fr_add(s[1], k1);
        sbox(s[0]);
        sbox(s[1]);
        mat_mul_external(s);
    }
    for (int i = 0; i < POSEIDON_PARTIAL; ++i) {
        Fr k0 = load_rk(POSEIDON_FULL_HALF + i, 0);
        s[0] = fr_add(s[0], k0);
        sbox(s[0]);
        mat_mul_internal(s);
    }
    for (int i = 0; i < POSEIDON_FULL_HALF; ++i) {
        Fr k0 = load_rk(POSEIDON_FULL_HALF + POSEIDON_PARTIAL + i, 0);
        Fr k1 = load_rk(POSEIDON_FULL_HALF + POSEIDON_PARTIAL + i, 1);
        s[0] = fr_add(s[0], k0);
        s[1] = fr_add(s[1], k1);
        sbox(s[0]);
        sbox(s[1]);
        mat_mul_external(s);
    }
}

// =============================================================================
// Bytes (BE) <-> Fr (Montgomery LE limbs) conversions.
// =============================================================================

__device__ __forceinline__ unsigned long long be_read64(const unsigned char *p) {
    unsigned long long v = 0;
    for (int b = 0; b < 8; ++b) v = (v << 8) | (unsigned long long)p[b];
    return v;
}

__device__ __forceinline__ Fr be_to_fr_mont(const unsigned char *be) {
    Fr x;
    x.l0 = be_read64(be + 24);
    x.l1 = be_read64(be + 16);
    x.l2 = be_read64(be + 8);
    x.l3 = be_read64(be + 0);
    for (int i = 0; i < 4; ++i) {
        if (cmp_q(x) < 0) break;
        unsigned long long br = 0;
        x.l0 = sbb(x.l0, Q0, br);
        x.l1 = sbb(x.l1, Q1, br);
        x.l2 = sbb(x.l2, Q2, br);
        x.l3 = sbb(x.l3, Q3, br);
    }
    Fr r2;
    r2.l0 = R_SQUARE_0; r2.l1 = R_SQUARE_1;
    r2.l2 = R_SQUARE_2; r2.l3 = R_SQUARE_3;
    return fr_mul(x, r2);
}

__device__ __forceinline__ void fr_mont_to_be(const Fr &x, unsigned char *be) {
    Fr one_reg;
    one_reg.l0 = 1; one_reg.l1 = 0; one_reg.l2 = 0; one_reg.l3 = 0;
    Fr r = fr_mul(x, one_reg);
    unsigned long long limbs[4] = {r.l0, r.l1, r.l2, r.l3};
    for (int i = 0; i < 4; ++i) {
        unsigned long long v = limbs[i];
        int off = 32 - 8 * (i + 1);
        for (int b = 7; b >= 0; --b) {
            be[off + b] = (unsigned char)(v & 0xff);
            v >>= 8;
        }
    }
}

// =============================================================================
// Per-thread compression body. Used by the global kernel and by the host
// polyfill loop.
// =============================================================================
__device__ static void poseidon2_hash2_one(const unsigned char *pair_in,
                                            unsigned char *out) {
    Fr s[2];
    s[0] = be_to_fr_mont(pair_in);
    s[1] = be_to_fr_mont(pair_in + 32);
    Fr saved_right = s[1];
    permute(s);
    Fr digest = fr_add(saved_right, s[1]);
    fr_mont_to_be(digest, out);
}

#if !KINET_POSEIDON_CUDA_HOST_POLYFILL
extern "C" __global__ void poseidon2_hash2_batch_kernel(
        const unsigned char *pairs,
        unsigned char       *outs,
        unsigned int         n) {
    unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    poseidon2_hash2_one(pairs + i * 64, outs + i * 32);
}
#endif

// =============================================================================
// Host driver C-ABI. On real CUDA hosts this calls cudaMalloc/cudaMemcpy/
// kernel<<<>>> dispatch; on polyfill hosts (no nvcc), it loops the same
// per-thread body on the CPU. Either way the output is byte-equal to the
// CPU oracle by construction (constants come from the CPU body).
// =============================================================================
extern "C" int poseidon2_hash2_cuda_batch(const unsigned char *pairs,
                                          unsigned char       *outs,
                                          unsigned long        n) {
    if (n == 0) return 0;
    if (!pairs || !outs) return -1;

#if KINET_POSEIDON_CUDA_HOST_POLYFILL
    for (unsigned long i = 0; i < n; ++i) {
        poseidon2_hash2_one(pairs + i * 64, outs + i * 32);
    }
    return 0;
#else
    unsigned char *d_pairs = nullptr, *d_outs = nullptr;
    cudaError_t st;
    st = cudaMalloc(&d_pairs, (size_t)n * 64);
    if (st != cudaSuccess) { return -2; }
    st = cudaMalloc(&d_outs,  (size_t)n * 32);
    if (st != cudaSuccess) { cudaFree(d_pairs); return -2; }
    st = cudaMemcpy(d_pairs, pairs, (size_t)n * 64, cudaMemcpyHostToDevice);
    if (st != cudaSuccess) { cudaFree(d_pairs); cudaFree(d_outs); return -3; }

    unsigned int tpb = 64;
    unsigned int blocks = (unsigned int)((n + tpb - 1) / tpb);
    poseidon2_hash2_batch_kernel<<<blocks, tpb>>>(d_pairs, d_outs, (unsigned int)n);
    st = cudaGetLastError();
    if (st != cudaSuccess) { cudaFree(d_pairs); cudaFree(d_outs); return -4; }
    st = cudaDeviceSynchronize();
    if (st != cudaSuccess) { cudaFree(d_pairs); cudaFree(d_outs); return -4; }

    st = cudaMemcpy(outs, d_outs, (size_t)n * 32, cudaMemcpyDeviceToHost);
    cudaFree(d_pairs);
    cudaFree(d_outs);
    if (st != cudaSuccess) { return -5; }
    return 0;
#endif
}

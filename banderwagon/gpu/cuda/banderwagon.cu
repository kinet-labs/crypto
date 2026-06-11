// First-party CUDA kernel for Banderwagon group operations.
//
// Mechanical port of banderwagon/gpu/metal/banderwagon.metal -- byte-for-byte
// equivalent to kinet::banderwagon::Element {add, double_self, scalar_mul} in
// banderwagon/cpp/element.cpp (twisted Edwards a*x^2 + y^2 = 1 + d*x^2*y^2
// over the BLS12-381 scalar field; a = -5; d = canonical gnark constant).
//
// The constant table (modulus, Montgomery R/R^2/qInvNeg, curve a/d, generator)
// is emitted from the CPU body via banderwagon_gen_gpu_constants ->
// banderwagon_const.cuh. There is exactly one source of truth across CPU,
// Metal, CUDA, and WGSL.
//
// Compile with nvcc compute_60+ on Linux/CUDA hosts. On hosts without nvcc
// (Apple, plain g++/clang++), this file compiles via a host-side polyfill
// that elides __device__/__global__/__host__ qualifiers and lets the kernel
// run on the CPU oracle path. Either path runs the identical kernel body and
// yields byte-equal output by construction.

#include <cstdint>
#include <cstring>

// Polyfill: when not building with nvcc, neutralize device qualifiers so the
// kernel body is plain C++. The driver below dispatches the same body via a
// host-side loop in that mode.
#ifndef __CUDA_ARCH__
#  ifndef KINET_BANDERWAGON_CUDA_HOST_POLYFILL
#    define KINET_BANDERWAGON_CUDA_HOST_POLYFILL 1
#  endif
#endif

#if KINET_BANDERWAGON_CUDA_HOST_POLYFILL
#  define __device__
#  define __global__
#  define __host__
#  define __forceinline__ inline
#endif

#include "banderwagon_const.cuh"  // FP_Q_*, FP_R*_*, CURVE_*_*, FP_QINV_NEG, ...

// =============================================================================
// 64x64 -> 128 multiply. nvcc emits __umul64hi on the GPU; the host polyfill
// uses __int128 (or a portable 32-bit fallback).
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

__device__ __forceinline__ unsigned long long adc(unsigned long long a,
                                                  unsigned long long b,
                                                  unsigned long long &carry) {
    unsigned long long s  = a + b;
    unsigned long long c1 = (s < a) ? 1ULL : 0ULL;
    unsigned long long s2 = s + carry;
    unsigned long long c2 = (s2 < s) ? 1ULL : 0ULL;
    carry = c1 + c2;
    return s2;
}

__device__ __forceinline__ unsigned long long sbb(unsigned long long a,
                                                  unsigned long long b,
                                                  unsigned long long &borrow) {
    unsigned long long d  = a - b;
    unsigned long long b1 = (a < b) ? 1ULL : 0ULL;
    unsigned long long d2 = d - borrow;
    unsigned long long b2 = (d < borrow) ? 1ULL : 0ULL;
    borrow = b1 + b2;
    return d2;
}

struct Fp { unsigned long long l0, l1, l2, l3; };
struct Pt { Fp X; Fp Y; Fp Z; };

__device__ __forceinline__ void fp_cond_sub_q(Fp &a) {
    unsigned long long br = 0;
    unsigned long long r0 = sbb(a.l0, FP_Q_0, br);
    unsigned long long r1 = sbb(a.l1, FP_Q_1, br);
    unsigned long long r2 = sbb(a.l2, FP_Q_2, br);
    unsigned long long r3 = sbb(a.l3, FP_Q_3, br);
    unsigned long long mask = br - 1ULL;
    a.l0 = (a.l0 & ~mask) | (r0 & mask);
    a.l1 = (a.l1 & ~mask) | (r1 & mask);
    a.l2 = (a.l2 & ~mask) | (r2 & mask);
    a.l3 = (a.l3 & ~mask) | (r3 & mask);
}

__device__ __forceinline__ void fp_cond_add_q(Fp &a, unsigned long long mask) {
    unsigned long long c = 0;
    a.l0 = adc(a.l0, FP_Q_0 & mask, c);
    a.l1 = adc(a.l1, FP_Q_1 & mask, c);
    a.l2 = adc(a.l2, FP_Q_2 & mask, c);
    a.l3 = adc(a.l3, FP_Q_3 & mask, c);
}

__device__ __forceinline__ Fp fp_add(const Fp &a, const Fp &b) {
    Fp r;
    unsigned long long c = 0;
    r.l0 = adc(a.l0, b.l0, c);
    r.l1 = adc(a.l1, b.l1, c);
    r.l2 = adc(a.l2, b.l2, c);
    r.l3 = adc(a.l3, b.l3, c);
    fp_cond_sub_q(r);
    return r;
}

__device__ __forceinline__ Fp fp_sub(const Fp &a, const Fp &b) {
    Fp r;
    unsigned long long br = 0;
    r.l0 = sbb(a.l0, b.l0, br);
    r.l1 = sbb(a.l1, b.l1, br);
    r.l2 = sbb(a.l2, b.l2, br);
    r.l3 = sbb(a.l3, b.l3, br);
    fp_cond_add_q(r, 0ULL - br);
    return r;
}

__device__ __forceinline__ Fp fp_mul(const Fp &a, const Fp &b) {
    const unsigned long long xl[4] = {a.l0, a.l1, a.l2, a.l3};
    const unsigned long long yl[4] = {b.l0, b.l1, b.l2, b.l3};
    const unsigned long long qq[4] = {FP_Q_0, FP_Q_1, FP_Q_2, FP_Q_3};

    unsigned long long t[5] = {0, 0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        const unsigned long long yi = yl[i];

        unsigned long long cy = 0;
        for (int j = 0; j < 4; ++j) {
            unsigned long long lo, hi;
            mul64(xl[j], yi, lo, hi);
            unsigned long long c1 = 0;
            unsigned long long s  = adc(t[j], lo, c1);
            unsigned long long c2 = 0;
            unsigned long long s2 = adc(s,    cy, c2);
            t[j] = s2;
            cy = hi + c1 + c2;
        }
        unsigned long long carry_out = 0;
        t[4] = adc(t[4], cy, carry_out);
        unsigned long long D = carry_out;

        unsigned long long m = t[0] * FP_QINV_NEG;

        cy = 0;
        for (int j = 0; j < 4; ++j) {
            unsigned long long lo, hi;
            mul64(m, qq[j], lo, hi);
            unsigned long long c1 = 0;
            unsigned long long s  = adc(t[j], lo, c1);
            unsigned long long c2 = 0;
            unsigned long long s2 = adc(s,    cy, c2);
            t[j] = s2;
            cy = hi + c1 + c2;
        }
        carry_out = 0;
        unsigned long long t3_new = adc(t[4], cy, carry_out);
        unsigned long long t4_new = adc(0ULL, D,  carry_out);

        t[0] = t[1]; t[1] = t[2]; t[2] = t[3];
        t[3] = t3_new;
        t[4] = t4_new;
    }

    Fp r;
    r.l0 = t[0]; r.l1 = t[1]; r.l2 = t[2]; r.l3 = t[3];
    if (t[4] != 0) {
        unsigned long long b = 0;
        r.l0 = sbb(r.l0, FP_Q_0, b);
        r.l1 = sbb(r.l1, FP_Q_1, b);
        r.l2 = sbb(r.l2, FP_Q_2, b);
        r.l3 = sbb(r.l3, FP_Q_3, b);
        return r;
    }
    fp_cond_sub_q(r);
    return r;
}

__device__ __forceinline__ Fp fp_square(const Fp &a) { return fp_mul(a, a); }

__device__ __forceinline__ Fp fp_zero() {
    Fp r; r.l0=0; r.l1=0; r.l2=0; r.l3=0; return r;
}
__device__ __forceinline__ Fp fp_one() {
    Fp r; r.l0=FP_R_0; r.l1=FP_R_1; r.l2=FP_R_2; r.l3=FP_R_3; return r;
}
__device__ __forceinline__ Fp curve_a_const() {
    Fp r; r.l0=CURVE_A_0; r.l1=CURVE_A_1; r.l2=CURVE_A_2; r.l3=CURVE_A_3;
    return r;
}
__device__ __forceinline__ Fp curve_d_const() {
    Fp r; r.l0=CURVE_D_0; r.l1=CURVE_D_1; r.l2=CURVE_D_2; r.l3=CURVE_D_3;
    return r;
}

__device__ __forceinline__ Pt pt_identity() {
    Pt p; p.X = fp_zero(); p.Y = fp_one(); p.Z = fp_one(); return p;
}

__device__ __forceinline__ Pt pt_add(const Pt &p1, const Pt &p2) {
    Fp d_const = curve_d_const();
    Fp a_const = curve_a_const();
    Fp A = fp_mul(p1.Z, p2.Z);
    Fp B = fp_square(A);
    Fp C = fp_mul(p1.X, p2.X);
    Fp D = fp_mul(p1.Y, p2.Y);
    Fp E = fp_mul(d_const, fp_mul(C, D));
    Fp F = fp_sub(B, E);
    Fp G = fp_add(B, E);
    Fp H = fp_add(p1.X, p1.Y);
    Fp I = fp_add(p2.X, p2.Y);

    Pt r;
    Fp t = fp_mul(H, I);
    t = fp_sub(t, C);
    t = fp_sub(t, D);
    t = fp_mul(t, A);
    r.X = fp_mul(t, F);

    Fp aC = fp_mul(a_const, C);
    Fp t2 = fp_sub(D, aC);
    t2 = fp_mul(t2, A);
    r.Y = fp_mul(t2, G);

    r.Z = fp_mul(F, G);
    return r;
}

__device__ __forceinline__ Pt pt_double(const Pt &p) {
    Fp a_const = curve_a_const();
    Fp XY = fp_add(p.X, p.Y);
    Fp B  = fp_square(XY);
    Fp C  = fp_square(p.X);
    Fp D  = fp_square(p.Y);
    Fp E  = fp_mul(a_const, C);
    Fp F  = fp_add(E, D);
    Fp H  = fp_square(p.Z);
    Fp twoH = fp_add(H, H);
    Fp J  = fp_sub(F, twoH);

    Pt r;
    Fp t = fp_sub(B, C);
    t = fp_sub(t, D);
    r.X = fp_mul(t, J);
    r.Y = fp_mul(F, fp_sub(E, D));
    r.Z = fp_mul(F, J);
    return r;
}

__device__ __forceinline__ void pt_cmov(Pt &dst, const Pt &src,
                                        unsigned long long mask) {
    dst.X.l0 = (dst.X.l0 & ~mask) | (src.X.l0 & mask);
    dst.X.l1 = (dst.X.l1 & ~mask) | (src.X.l1 & mask);
    dst.X.l2 = (dst.X.l2 & ~mask) | (src.X.l2 & mask);
    dst.X.l3 = (dst.X.l3 & ~mask) | (src.X.l3 & mask);
    dst.Y.l0 = (dst.Y.l0 & ~mask) | (src.Y.l0 & mask);
    dst.Y.l1 = (dst.Y.l1 & ~mask) | (src.Y.l1 & mask);
    dst.Y.l2 = (dst.Y.l2 & ~mask) | (src.Y.l2 & mask);
    dst.Y.l3 = (dst.Y.l3 & ~mask) | (src.Y.l3 & mask);
    dst.Z.l0 = (dst.Z.l0 & ~mask) | (src.Z.l0 & mask);
    dst.Z.l1 = (dst.Z.l1 & ~mask) | (src.Z.l1 & mask);
    dst.Z.l2 = (dst.Z.l2 & ~mask) | (src.Z.l2 & mask);
    dst.Z.l3 = (dst.Z.l3 & ~mask) | (src.Z.l3 & mask);
}

__device__ __forceinline__ Pt pt_scalar_mul(const Pt &p,
                                            const std::uint8_t *s_le) {
    Pt acc  = pt_identity();
    Pt base = p;
    for (int byte_idx = 0; byte_idx < 32; ++byte_idx) {
        std::uint8_t b = s_le[byte_idx];
        for (int bit = 0; bit < 8; ++bit) {
            unsigned long long one_or_zero =
                (unsigned long long)((b >> bit) & 1u);
            unsigned long long mask = 0ULL - one_or_zero;
            Pt sum = pt_add(acc, base);
            pt_cmov(acc, sum, mask);
            base = pt_double(base);
        }
    }
    return acc;
}

__device__ __forceinline__ Fp read_fp_limbs(const std::uint8_t *p) {
    Fp r;
    auto rd = [&](int o) -> unsigned long long {
        return ((unsigned long long)p[o])         | ((unsigned long long)p[o+1] << 8)
             | ((unsigned long long)p[o+2] << 16) | ((unsigned long long)p[o+3] << 24)
             | ((unsigned long long)p[o+4] << 32) | ((unsigned long long)p[o+5] << 40)
             | ((unsigned long long)p[o+6] << 48) | ((unsigned long long)p[o+7] << 56);
    };
    r.l0 = rd(0); r.l1 = rd(8); r.l2 = rd(16); r.l3 = rd(24);
    return r;
}

__device__ __forceinline__ void write_fp_limbs(const Fp &x, std::uint8_t *p) {
    auto wr = [&](unsigned long long v, int o) {
        for (int i = 0; i < 8; ++i) { p[o+i] = (std::uint8_t)(v & 0xff); v >>= 8; }
    };
    wr(x.l0, 0); wr(x.l1, 8); wr(x.l2, 16); wr(x.l3, 24);
}

__device__ __forceinline__ Pt read_pt(const std::uint8_t *p) {
    Pt r;
    r.X = read_fp_limbs(p);
    r.Y = read_fp_limbs(p + 32);
    r.Z = read_fp_limbs(p + 64);
    return r;
}

__device__ __forceinline__ void write_pt(const Pt &p, std::uint8_t *out) {
    write_fp_limbs(p.X, out);
    write_fp_limbs(p.Y, out + 32);
    write_fp_limbs(p.Z, out + 64);
}

__device__ static void bw_add_one(const std::uint8_t *pair_in,
                                   std::uint8_t       *out) {
    Pt P = read_pt(pair_in);
    Pt Q = read_pt(pair_in + 96);
    Pt R = pt_add(P, Q);
    write_pt(R, out);
}

__device__ static void bw_double_one(const std::uint8_t *pt_in,
                                      std::uint8_t       *out) {
    Pt P = read_pt(pt_in);
    Pt R = pt_double(P);
    write_pt(R, out);
}

__device__ static void bw_smul_one(const std::uint8_t *pt_in,
                                    const std::uint8_t *scalar_in,
                                    std::uint8_t       *out) {
    Pt P = read_pt(pt_in);
    Pt R = pt_scalar_mul(P, scalar_in);
    write_pt(R, out);
}

__device__ static void bw_msm_one(const std::uint8_t *pts,
                                   const std::uint8_t *scalars_b,
                                   std::uint8_t       *out,
                                   unsigned int        n) {
    Pt acc = pt_identity();
    for (unsigned int i = 0; i < n; ++i) {
        Pt P    = read_pt(pts + (size_t)i * 96);
        Pt term = pt_scalar_mul(P, scalars_b + (size_t)i * 32);
        acc = pt_add(acc, term);
    }
    write_pt(acc, out);
}

#if !KINET_BANDERWAGON_CUDA_HOST_POLYFILL
extern "C" __global__ void banderwagon_add_kernel(
        const std::uint8_t *pairs, std::uint8_t *outs, unsigned int n) {
    unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    bw_add_one(pairs + (size_t)i * 192, outs + (size_t)i * 96);
}
extern "C" __global__ void banderwagon_double_kernel(
        const std::uint8_t *pts, std::uint8_t *outs, unsigned int n) {
    unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    bw_double_one(pts + (size_t)i * 96, outs + (size_t)i * 96);
}
extern "C" __global__ void banderwagon_smul_kernel(
        const std::uint8_t *pts, const std::uint8_t *scalars,
        std::uint8_t *outs, unsigned int n) {
    unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    bw_smul_one(pts + (size_t)i * 96, scalars + (size_t)i * 32,
                outs + (size_t)i * 96);
}
extern "C" __global__ void banderwagon_msm_kernel(
        const std::uint8_t *pts, const std::uint8_t *scalars,
        std::uint8_t *outs, unsigned int n, unsigned int M) {
    unsigned int b = blockIdx.x * blockDim.x + threadIdx.x;
    if (b >= M) return;
    bw_msm_one(pts, scalars + (size_t)b * n * 32, outs + (size_t)b * 96, n);
}
#endif

extern "C" int banderwagon_cuda_add_batch(const std::uint8_t *pairs,
                                          std::uint8_t       *outs,
                                          unsigned long       n) {
    if (n == 0) return 0;
    if (!pairs || !outs) return -1;

#if KINET_BANDERWAGON_CUDA_HOST_POLYFILL
    for (unsigned long i = 0; i < n; ++i) {
        bw_add_one(pairs + (size_t)i * 192, outs + (size_t)i * 96);
    }
    return 0;
#else
    std::uint8_t *d_in = nullptr, *d_out = nullptr;
    cudaError_t st;
    st = cudaMalloc(&d_in,  (size_t)n * 192); if (st != cudaSuccess) return -2;
    st = cudaMalloc(&d_out, (size_t)n * 96);
    if (st != cudaSuccess) { cudaFree(d_in); return -2; }
    st = cudaMemcpy(d_in, pairs, (size_t)n * 192, cudaMemcpyHostToDevice);
    if (st != cudaSuccess) { cudaFree(d_in); cudaFree(d_out); return -3; }
    unsigned int tpb = 64;
    unsigned int blocks = (unsigned int)((n + tpb - 1) / tpb);
    banderwagon_add_kernel<<<blocks, tpb>>>(d_in, d_out, (unsigned int)n);
    st = cudaGetLastError();
    if (st == cudaSuccess) st = cudaDeviceSynchronize();
    if (st != cudaSuccess) { cudaFree(d_in); cudaFree(d_out); return -4; }
    st = cudaMemcpy(outs, d_out, (size_t)n * 96, cudaMemcpyDeviceToHost);
    cudaFree(d_in); cudaFree(d_out);
    return (st != cudaSuccess) ? -5 : 0;
#endif
}

extern "C" int banderwagon_cuda_double_batch(const std::uint8_t *pts,
                                             std::uint8_t       *outs,
                                             unsigned long       n) {
    if (n == 0) return 0;
    if (!pts || !outs) return -1;

#if KINET_BANDERWAGON_CUDA_HOST_POLYFILL
    for (unsigned long i = 0; i < n; ++i) {
        bw_double_one(pts + (size_t)i * 96, outs + (size_t)i * 96);
    }
    return 0;
#else
    std::uint8_t *d_in = nullptr, *d_out = nullptr;
    cudaError_t st;
    st = cudaMalloc(&d_in,  (size_t)n * 96); if (st != cudaSuccess) return -2;
    st = cudaMalloc(&d_out, (size_t)n * 96);
    if (st != cudaSuccess) { cudaFree(d_in); return -2; }
    st = cudaMemcpy(d_in, pts, (size_t)n * 96, cudaMemcpyHostToDevice);
    if (st != cudaSuccess) { cudaFree(d_in); cudaFree(d_out); return -3; }
    unsigned int tpb = 64;
    unsigned int blocks = (unsigned int)((n + tpb - 1) / tpb);
    banderwagon_double_kernel<<<blocks, tpb>>>(d_in, d_out, (unsigned int)n);
    st = cudaGetLastError();
    if (st == cudaSuccess) st = cudaDeviceSynchronize();
    if (st != cudaSuccess) { cudaFree(d_in); cudaFree(d_out); return -4; }
    st = cudaMemcpy(outs, d_out, (size_t)n * 96, cudaMemcpyDeviceToHost);
    cudaFree(d_in); cudaFree(d_out);
    return (st != cudaSuccess) ? -5 : 0;
#endif
}

extern "C" int banderwagon_cuda_smul_batch(const std::uint8_t *pts,
                                           const std::uint8_t *scalars,
                                           std::uint8_t       *outs,
                                           unsigned long       n) {
    if (n == 0) return 0;
    if (!pts || !scalars || !outs) return -1;

#if KINET_BANDERWAGON_CUDA_HOST_POLYFILL
    for (unsigned long i = 0; i < n; ++i) {
        bw_smul_one(pts     + (size_t)i * 96,
                    scalars + (size_t)i * 32,
                    outs    + (size_t)i * 96);
    }
    return 0;
#else
    std::uint8_t *d_pts = nullptr, *d_scl = nullptr, *d_out = nullptr;
    cudaError_t st;
    st = cudaMalloc(&d_pts, (size_t)n * 96); if (st != cudaSuccess) return -2;
    st = cudaMalloc(&d_scl, (size_t)n * 32);
    if (st != cudaSuccess) { cudaFree(d_pts); return -2; }
    st = cudaMalloc(&d_out, (size_t)n * 96);
    if (st != cudaSuccess) { cudaFree(d_pts); cudaFree(d_scl); return -2; }
    st = cudaMemcpy(d_pts, pts,     (size_t)n * 96, cudaMemcpyHostToDevice);
    if (st == cudaSuccess)
        st = cudaMemcpy(d_scl, scalars, (size_t)n * 32, cudaMemcpyHostToDevice);
    if (st != cudaSuccess) {
        cudaFree(d_pts); cudaFree(d_scl); cudaFree(d_out); return -3;
    }
    unsigned int tpb = 32;
    unsigned int blocks = (unsigned int)((n + tpb - 1) / tpb);
    banderwagon_smul_kernel<<<blocks, tpb>>>(d_pts, d_scl, d_out,
                                             (unsigned int)n);
    st = cudaGetLastError();
    if (st == cudaSuccess) st = cudaDeviceSynchronize();
    if (st != cudaSuccess) {
        cudaFree(d_pts); cudaFree(d_scl); cudaFree(d_out); return -4;
    }
    st = cudaMemcpy(outs, d_out, (size_t)n * 96, cudaMemcpyDeviceToHost);
    cudaFree(d_pts); cudaFree(d_scl); cudaFree(d_out);
    return (st != cudaSuccess) ? -5 : 0;
#endif
}

extern "C" int banderwagon_cuda_msm_batch(const std::uint8_t *pts,
                                          const std::uint8_t *scalars,
                                          std::uint8_t       *outs,
                                          unsigned long       n,
                                          unsigned long       M) {
    if (n == 0 || M == 0) return 0;
    if (!pts || !scalars || !outs) return -1;

#if KINET_BANDERWAGON_CUDA_HOST_POLYFILL
    for (unsigned long b = 0; b < M; ++b) {
        bw_msm_one(pts,
                   scalars + (size_t)b * n * 32,
                   outs    + (size_t)b * 96,
                   (unsigned int)n);
    }
    return 0;
#else
    std::uint8_t *d_pts = nullptr, *d_scl = nullptr, *d_out = nullptr;
    cudaError_t st;
    st = cudaMalloc(&d_pts, (size_t)n * 96); if (st != cudaSuccess) return -2;
    st = cudaMalloc(&d_scl, (size_t)M * n * 32);
    if (st != cudaSuccess) { cudaFree(d_pts); return -2; }
    st = cudaMalloc(&d_out, (size_t)M * 96);
    if (st != cudaSuccess) { cudaFree(d_pts); cudaFree(d_scl); return -2; }
    st = cudaMemcpy(d_pts, pts,     (size_t)n * 96,        cudaMemcpyHostToDevice);
    if (st == cudaSuccess)
        st = cudaMemcpy(d_scl, scalars, (size_t)M * n * 32, cudaMemcpyHostToDevice);
    if (st != cudaSuccess) {
        cudaFree(d_pts); cudaFree(d_scl); cudaFree(d_out); return -3;
    }
    unsigned int tpb = 32;
    unsigned int blocks = (unsigned int)((M + tpb - 1) / tpb);
    banderwagon_msm_kernel<<<blocks, tpb>>>(d_pts, d_scl, d_out,
                                            (unsigned int)n, (unsigned int)M);
    st = cudaGetLastError();
    if (st == cudaSuccess) st = cudaDeviceSynchronize();
    if (st != cudaSuccess) {
        cudaFree(d_pts); cudaFree(d_scl); cudaFree(d_out); return -4;
    }
    st = cudaMemcpy(outs, d_out, (size_t)M * 96, cudaMemcpyDeviceToHost);
    cudaFree(d_pts); cudaFree(d_scl); cudaFree(d_out);
    return (st != cudaSuccess) ? -5 : 0;
#endif
}

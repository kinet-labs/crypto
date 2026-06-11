// Host-side CUDA driver for bn254 kernels.
//
// Two compile modes:
//   1. KINET_BN254_HAVE_CUDA defined: dispatches kernels via cudaMemcpy/launch,
//      identical algorithm to the CPU oracle (bn254/cpp/*.hpp), byte-equal
//      results.
//   2. KINET_BN254_HAVE_CUDA undefined: runs the CPU oracle directly so the
//      determinism harness still passes 100/100. Reports unavailable via
//      kinet_bn254_cuda_available() so tests can label the path correctly.
//
// The byte-equality CI runner enables KINET_BN254_HAVE_CUDA and exercises the
// real kernel; on CPU-only laptops/CI the same 100 deterministic inputs flow
// through the CPU oracle path and the harness still verifies the wire format.

#include "bn254_driver_cuda.h"
#include "bn254.hpp"

#include <cstdint>
#include <cstring>

#ifdef KINET_BN254_HAVE_CUDA
#include <cuda_runtime.h>

extern "C" {
__global__ void k_g1_add(const unsigned long long*, const unsigned long long*,
                         unsigned long long*, unsigned);
__global__ void k_g1_mul(const unsigned long long*, const unsigned long long*,
                         unsigned long long*, unsigned);
__global__ void k_svdw  (const unsigned long long*, unsigned long long*, unsigned);
__global__ void k_fp_mul(const unsigned long long*, const unsigned long long*,
                         unsigned long long*, unsigned);
__global__ void k_fp2_mul(const unsigned long long*, const unsigned long long*,
                          unsigned long long*, unsigned);
__global__ void k_fp12_mul(const unsigned long long*, const unsigned long long*,
                           unsigned long long*, unsigned);
__global__ void k_miller_iter(const unsigned long long*, unsigned long long*, unsigned);
__global__ void k_pairing(const unsigned long long*, const unsigned long long*,
                          unsigned long long*, unsigned);
}

namespace {

bool device_present() {
    int n = 0;
    cudaError_t e = cudaGetDeviceCount(&n);
    return (e == cudaSuccess && n > 0);
}

unsigned grid_for(unsigned n, unsigned tg) { return (n + tg - 1) / tg; }

template <typename Kernel>
int dispatch3(Kernel kf, const void* a, const void* b, void* out,
              size_t bytes_in_a, size_t bytes_in_b, size_t bytes_out, unsigned n) {
    void *dA=nullptr,*dB=nullptr,*dO=nullptr;
    if (cudaMalloc(&dA, bytes_in_a) != cudaSuccess) return -1;
    if (cudaMalloc(&dB, bytes_in_b) != cudaSuccess) { cudaFree(dA); return -1; }
    if (cudaMalloc(&dO, bytes_out)  != cudaSuccess) { cudaFree(dA); cudaFree(dB); return -1; }
    cudaMemcpy(dA, a, bytes_in_a, cudaMemcpyHostToDevice);
    cudaMemcpy(dB, b, bytes_in_b, cudaMemcpyHostToDevice);
    unsigned tg = 64; unsigned grid = grid_for(n, tg);
    kf<<<grid, tg>>>((const unsigned long long*)dA, (const unsigned long long*)dB,
                     (unsigned long long*)dO, n);
    cudaDeviceSynchronize();
    cudaMemcpy(out, dO, bytes_out, cudaMemcpyDeviceToHost);
    cudaFree(dA); cudaFree(dB); cudaFree(dO);
    return 0;
}

template <typename Kernel>
int dispatch2(Kernel kf, const void* a, void* out,
              size_t bytes_in, size_t bytes_out, unsigned n) {
    void *dA=nullptr,*dO=nullptr;
    if (cudaMalloc(&dA, bytes_in)  != cudaSuccess) return -1;
    if (cudaMalloc(&dO, bytes_out) != cudaSuccess) { cudaFree(dA); return -1; }
    cudaMemcpy(dA, a, bytes_in, cudaMemcpyHostToDevice);
    unsigned tg = 64; unsigned grid = grid_for(n, tg);
    kf<<<grid, tg>>>((const unsigned long long*)dA, (unsigned long long*)dO, n);
    cudaDeviceSynchronize();
    cudaMemcpy(out, dO, bytes_out, cudaMemcpyDeviceToHost);
    cudaFree(dA); cudaFree(dO);
    return 0;
}

}  // namespace

extern "C" {

int kinet_bn254_cuda_available(void) { return device_present() ? 1 : 0; }

int kinet_bn254_cuda_g1_add(const void* a, const void* b, void* out, unsigned n) {
    if (!device_present()) return -1;
    return dispatch3(k_g1_add, a, b, out, 9*8*n, 9*8*n, 9*8*n, n);
}

int kinet_bn254_cuda_g1_mul(const void* points, const void* scalars, void* out, unsigned n) {
    if (!device_present()) return -1;
    return dispatch3(k_g1_mul, points, scalars, out, 9*8*n, 4*8*n, 9*8*n, n);
}

int kinet_bn254_cuda_svdw(const void* u_in, void* out, unsigned n) {
    if (!device_present()) return -1;
    return dispatch2(k_svdw, u_in, out, 4*8*n, 9*8*n, n);
}

int kinet_bn254_cuda_fp_mul(const void* a, const void* b, void* out, unsigned n) {
    if (!device_present()) return -1;
    return dispatch3(k_fp_mul, a, b, out, 4*8*n, 4*8*n, 4*8*n, n);
}

int kinet_bn254_cuda_fp2_mul(const void* a, const void* b, void* out, unsigned n) {
    if (!device_present()) return -1;
    return dispatch3(k_fp2_mul, a, b, out, 8*8*n, 8*8*n, 8*8*n, n);
}

int kinet_bn254_cuda_fp12_mul(const void* a, const void* b, void* out, unsigned n) {
    if (!device_present()) return -1;
    return dispatch3(k_fp12_mul, a, b, out, 48*8*n, 48*8*n, 48*8*n, n);
}

int kinet_bn254_cuda_miller_iter(const void* in_p, void* out, unsigned n) {
    if (!device_present()) return -1;
    return dispatch2(k_miller_iter, in_p, out, 48*8*n, 48*8*n, n);
}

int kinet_bn254_cuda_pairing(const void* P, const void* Q, void* out, unsigned n) {
    if (!device_present()) return -1;
    return dispatch3(k_pairing, P, Q, out, 9*8*n, 18*8*n, 48*8*n, n);
}

}  // extern "C"

#else  // KINET_BN254_HAVE_CUDA undefined: CPU-oracle path

#include "bn254_fp.hpp"
#include "bn254_fp2.hpp"
#include "bn254_fp12.hpp"
#include "bn254_g1.hpp"
#include "bn254_g2.hpp"
#include "bn254_hash_to_curve.hpp"
#include "bn254_pairing.hpp"

namespace {

using kinet::crypto::bn254::U256;
using kinet::crypto::bn254::Fp2;
using kinet::crypto::bn254::Fp12;
using kinet::crypto::bn254::G1Affine;
using kinet::crypto::bn254::G1Jac;
using kinet::crypto::bn254::G2Affine;

inline U256 load_u256(const std::uint64_t* p) {
    U256 r; r.limbs[0]=p[0]; r.limbs[1]=p[1]; r.limbs[2]=p[2]; r.limbs[3]=p[3];
    return r;
}

inline void store_aff(std::uint64_t* p, const G1Affine& a) {
    p[0]=a.x.limbs[0]; p[1]=a.x.limbs[1]; p[2]=a.x.limbs[2]; p[3]=a.x.limbs[3];
    p[4]=a.y.limbs[0]; p[5]=a.y.limbs[1]; p[6]=a.y.limbs[2]; p[7]=a.y.limbs[3];
    p[8] = a.infinity ? 1ULL : 0ULL;
}

inline G1Affine load_aff(const std::uint64_t* p) {
    G1Affine a;
    a.x = load_u256(p);
    a.y = load_u256(p + 4);
    a.infinity = (p[8] != 0);
    return a;
}

inline Fp2 load_fp2(const std::uint64_t* p) {
    Fp2 r;
    for (int i = 0; i < 4; ++i) { r.a0.limbs[i] = p[i]; r.a1.limbs[i] = p[4+i]; }
    return r;
}
inline void store_fp2(std::uint64_t* p, const Fp2& x) {
    for (int i = 0; i < 4; ++i) { p[i] = x.a0.limbs[i]; p[4+i] = x.a1.limbs[i]; }
}
inline G2Affine load_g2(const std::uint64_t* p) {
    G2Affine a;
    a.x = load_fp2(p);
    a.y = load_fp2(p + 8);
    a.infinity = (p[16] != 0);
    return a;
}
inline Fp12 load_fp12(const std::uint64_t* p) {
    Fp12 r;
    r.c0.b0 = load_fp2(p +  0);
    r.c0.b1 = load_fp2(p +  8);
    r.c0.b2 = load_fp2(p + 16);
    r.c1.b0 = load_fp2(p + 24);
    r.c1.b1 = load_fp2(p + 32);
    r.c1.b2 = load_fp2(p + 40);
    return r;
}
inline void store_fp12(std::uint64_t* p, const Fp12& x) {
    store_fp2(p +  0, x.c0.b0);
    store_fp2(p +  8, x.c0.b1);
    store_fp2(p + 16, x.c0.b2);
    store_fp2(p + 24, x.c1.b0);
    store_fp2(p + 32, x.c1.b1);
    store_fp2(p + 40, x.c1.b2);
}

}  // namespace

extern "C" {

int kinet_bn254_cuda_available(void) { return 0; }

int kinet_bn254_cuda_g1_add(const void* a, const void* b, void* out, unsigned n) {
    auto* pa = (const std::uint64_t*)a;
    auto* pb = (const std::uint64_t*)b;
    auto* po = (std::uint64_t*)out;
    for (unsigned i = 0; i < n; ++i) {
        G1Affine A = load_aff(pa + i*9);
        G1Affine B = load_aff(pb + i*9);
        G1Jac    S = kinet::crypto::bn254::g1_add(
                        kinet::crypto::bn254::g1_to_jac(A),
                        kinet::crypto::bn254::g1_to_jac(B));
        store_aff(po + i*9, kinet::crypto::bn254::g1_to_affine(S));
    }
    return 0;
}

int kinet_bn254_cuda_g1_mul(const void* points, const void* scalars, void* out, unsigned n) {
    auto* pp = (const std::uint64_t*)points;
    auto* ps = (const std::uint64_t*)scalars;
    auto* po = (std::uint64_t*)out;
    for (unsigned i = 0; i < n; ++i) {
        G1Affine P = load_aff(pp + i*9);
        U256     k = load_u256(ps + i*4);
        store_aff(po + i*9, kinet::crypto::bn254::g1_to_affine(
            kinet::crypto::bn254::g1_scalar_mul(P, k)));
    }
    return 0;
}

int kinet_bn254_cuda_svdw(const void* u_in, void* out, unsigned n) {
    auto* pu = (const std::uint64_t*)u_in;
    auto* po = (std::uint64_t*)out;
    for (unsigned i = 0; i < n; ++i) {
        U256 u = load_u256(pu + i*4);
        G1Affine R = kinet::crypto::bn254::h2c::map_to_curve_svdw(u);
        store_aff(po + i*9, R);
    }
    return 0;
}

int kinet_bn254_cuda_fp_mul(const void* a, const void* b, void* out, unsigned n) {
    auto* pa = (const std::uint64_t*)a;
    auto* pb = (const std::uint64_t*)b;
    auto* po = (std::uint64_t*)out;
    for (unsigned i = 0; i < n; ++i) {
        U256 A = load_u256(pa + i*4);
        U256 B = load_u256(pb + i*4);
        U256 R = kinet::crypto::bn254::fp_mul(A, B);
        po[i*4+0]=R.limbs[0]; po[i*4+1]=R.limbs[1];
        po[i*4+2]=R.limbs[2]; po[i*4+3]=R.limbs[3];
    }
    return 0;
}

int kinet_bn254_cuda_fp2_mul(const void* a, const void* b, void* out, unsigned n) {
    auto* pa = (const std::uint64_t*)a;
    auto* pb = (const std::uint64_t*)b;
    auto* po = (std::uint64_t*)out;
    for (unsigned i = 0; i < n; ++i) {
        store_fp2(po + i*8,
            kinet::crypto::bn254::fp2_mul(load_fp2(pa + i*8), load_fp2(pb + i*8)));
    }
    return 0;
}

int kinet_bn254_cuda_fp12_mul(const void* a, const void* b, void* out, unsigned n) {
    auto* pa = (const std::uint64_t*)a;
    auto* pb = (const std::uint64_t*)b;
    auto* po = (std::uint64_t*)out;
    for (unsigned i = 0; i < n; ++i) {
        store_fp12(po + i*48,
            kinet::crypto::bn254::fp12_mul(load_fp12(pa + i*48), load_fp12(pb + i*48)));
    }
    return 0;
}

int kinet_bn254_cuda_miller_iter(const void* in_p, void* out, unsigned n) {
    auto* pi = (const std::uint64_t*)in_p;
    auto* po = (std::uint64_t*)out;
    for (unsigned i = 0; i < n; ++i) {
        Fp12 z = load_fp12(pi + i*48);
        for (int k = 0; k < 100; ++k)
            z = kinet::crypto::bn254::cyclotomic_sqr_public(z);
        store_fp12(po + i*48, z);
    }
    return 0;
}

int kinet_bn254_cuda_pairing(const void* P, const void* Q, void* out, unsigned n) {
    auto* pP = (const std::uint64_t*)P;
    auto* pQ = (const std::uint64_t*)Q;
    auto* po = (std::uint64_t*)out;
    for (unsigned i = 0; i < n; ++i) {
        G1Affine pi = load_aff(pP + i*9);
        G2Affine qi = load_g2(pQ + i*18);
        Fp12 r = kinet::crypto::bn254::multi_pair(&pi, &qi, 1);
        store_fp12(po + i*48, r);
    }
    return 0;
}

}  // extern "C"

#endif  // KINET_BN254_HAVE_CUDA

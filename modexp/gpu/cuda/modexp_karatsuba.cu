// kinet-labs/crypto: Karatsuba multiplication kernel (CUDA / nvcc-compatible C++).
// One-shot full multi-precision multiply r[2n] = x[n] * y[n] for n in
// [16, 64] limbs (1024..4096 bits). Native 64-bit integer arithmetic is
// available on CUDA so we use uint64_t and __umul64hi directly.
//
// Parallelization (matching the Metal kernel's host orchestration):
//   * One block per multiplication.
//   * Block-cooperative computation of three half-sized sub-products of
//     Karatsuba (z0, z1', z2). The host driver issues three child kernels
//     in parallel (different streams) when the Karatsuba split is profitable;
//     the kernel below is the schoolbook base case dispatched per sub-product.
//
// This file compiles as plain C++ when CRYPTO_ENABLE_CUDA is OFF (host
// polyfill: same kernel body, single-threaded). The polyfill produces
// byte-identical output to the GPU path by construction.

#if defined(__CUDACC__)
  #define KINET_KKERNEL extern "C" __global__
  #define KINET_KDEVICE __device__
#else
  // Host polyfill -- compiled as plain C++ when CUDA isn't enabled.
  #define KINET_KKERNEL extern "C"
  #define KINET_KDEVICE static inline
  #include <cstdint>
#endif

#if !defined(__CUDACC__)
// Host umul64hi polyfill.
KINET_KDEVICE uint64_t kinet_umul64hi(uint64_t a, uint64_t b)
{
    // Use the standard 32x32 decomposition.
    const uint64_t a_lo = (uint32_t)a;
    const uint64_t a_hi = a >> 32;
    const uint64_t b_lo = (uint32_t)b;
    const uint64_t b_hi = b >> 32;

    const uint64_t ll = a_lo * b_lo;
    const uint64_t lh = a_lo * b_hi;
    const uint64_t hl = a_hi * b_lo;
    const uint64_t hh = a_hi * b_hi;

    const uint64_t mid = (ll >> 32) + (lh & 0xFFFFFFFFULL) + (hl & 0xFFFFFFFFULL);
    return hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}
#define kinet_umul_hi kinet_umul64hi
#else
#include <cstdint>
#define kinet_umul_hi __umul64hi
#endif

// Full schoolbook product: r[2n] = x[n] * y[n].
// Caller-allocated r is zero-initialised before launch (host driver clears it).
//
// Block strategy: one block performs the full product. Thread tid in [0,n)
// computes one j-row of the partial product. Carry chain across rows is
// handled by serializing the column adds inside a single warp (warp-level
// __shfl propagation), but for simplicity and byte-equivalence with CPU
// we use the canonical row-major schoolbook here. Performance optimizations
// (Comba diagonal, warp-level carry) live in a future kernel; this version
// targets correctness.
KINET_KKERNEL void modexp_kara_mul(
    const uint64_t* __restrict__ x,
    const uint64_t* __restrict__ y,
    uint64_t*       __restrict__ r,
    unsigned                     n)
{
#if defined(__CUDACC__)
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
#endif

    // Clear r.
    for (unsigned k = 0; k < 2 * n; ++k) r[k] = 0;

    // Schoolbook: one block, one thread does the work. The Karatsuba split
    // (3 sub-multiplies) is performed by the host driver issuing 3 launches
    // in parallel; this kernel is the base case those launches use.
    for (unsigned j = 0; j < n; ++j)
    {
        uint64_t carry = 0;
        for (unsigned i = 0; i < n; ++i)
        {
#if defined(__CUDACC__)
            // 64x64 -> 128 bits via two intrinsics.
            const uint64_t lo = x[i] * y[j];
            const uint64_t hi = kinet_umul_hi(x[i], y[j]);
#else
            // Host polyfill: __uint128_t is a GCC/Clang extension.
            const __uint128_t prod = (__uint128_t)x[i] * (__uint128_t)y[j];
            const uint64_t lo = (uint64_t)prod;
            const uint64_t hi = (uint64_t)(prod >> 64);
#endif
            const uint64_t s1 = lo + r[i + j];
            const uint64_t c1 = (s1 < lo) ? 1 : 0;
            const uint64_t s2 = s1 + carry;
            const uint64_t c2 = (s2 < s1) ? 1 : 0;
            r[i + j] = s2;
            carry = hi + c1 + c2;  // hi <= 2^64 - 2, so carries don't overflow
        }
        r[j + n] = carry;
    }
}

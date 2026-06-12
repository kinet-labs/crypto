// Montgomery batch inversion for secp256k1 base field (Fp) and scalar field
// (Fn) -- CUDA port of secp256k1_batch_inv.metal. Output byte-equal to:
//   * cpp/batch_inv.hpp (CPU canonical body)
//   * gpu/metal/secp256k1_batch_inv.metal (Metal kernel)
//
// Single-thread dispatch (one workgroup of one thread) preserves byte-equal
// determinism with the CPU implementation. The acceleration win is freeing
// the host CPU for other pipeline stages, not raw throughput.
//
// Compile-guarded: when __CUDACC__ is unset (e.g. on macOS hosts without the
// CUDA toolkit), this TU emits a NOTIMPL stub so the umbrella library still
// links. Real device code is built on the linux-amd64 CI runner.

#include <cstddef>
#include <cstdint>
#include <cstring>

#ifdef __CUDACC__
#include <cuda_runtime.h>
#endif

namespace {

// =============================================================================
// 256-bit field constants -- byte-equal to secp256k1_batch_inv.metal
// =============================================================================

struct uint256 { uint64_t limbs[4]; };

#ifdef __CUDACC__
#define KINET_DEV __device__
#else
#define KINET_DEV
#endif

KINET_DEV static const uint256 P_MOD = {{
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
}};
KINET_DEV static const uint256 N_MOD = {{
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
}};
KINET_DEV static const uint64_t P_INV = 0xD838091DD2253531ULL;
KINET_DEV static const uint64_t N_INV = 0x4B0DFF665588B13FULL;
KINET_DEV static const uint256 R2_N = {{
    0x896CF21467D7D140ULL, 0x741496C20E7CF878ULL,
    0xE697F5E45BCD07C6ULL, 0x9D671CD581C69BC5ULL
}};
KINET_DEV static const uint256 ONE_MONT_P = {{
    0x00000001000003D1ULL, 0ULL, 0ULL, 0ULL
}};
KINET_DEV static const uint64_t P_M2[4] = {
    0xFFFFFFFEFFFFFC2DULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
};
KINET_DEV static const uint64_t N_M2[4] = {
    0xBFD25E8CD036413FULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
};
KINET_DEV static const uint256 ONE = {{ 1ULL, 0ULL, 0ULL, 0ULL }};

// =============================================================================
// 256-bit arithmetic helpers (host-and-device, byte-equal to Metal)
// =============================================================================

#ifdef __CUDACC__
__device__ static int u256_cmp(uint256 a, uint256 b) {
#else
static int u256_cmp(uint256 a, uint256 b) {
#endif
    for (int i = 3; i >= 0; --i) {
        if (a.limbs[i] < b.limbs[i]) return -1;
        if (a.limbs[i] > b.limbs[i]) return 1;
    }
    return 0;
}

#ifdef __CUDACC__
__device__ static void mul64(uint64_t a, uint64_t b, uint64_t& lo, uint64_t& hi) {
    unsigned __int128 prod = (unsigned __int128)a * (unsigned __int128)b;
    lo = (uint64_t)prod;
    hi = (uint64_t)(prod >> 64);
}
#else
static void mul64(uint64_t a, uint64_t b, uint64_t& lo, uint64_t& hi) {
    uint64_t al = a & 0xFFFFFFFFULL, ah = a >> 32;
    uint64_t bl = b & 0xFFFFFFFFULL, bh = b >> 32;
    uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    uint64_t mid = (ll >> 32) + (lh & 0xFFFFFFFFULL) + (hl & 0xFFFFFFFFULL);
    lo = (ll & 0xFFFFFFFFULL) | (mid << 32);
    hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}
#endif

#ifdef __CUDACC__
__device__ static uint64_t addc(uint64_t a, uint64_t b, uint64_t c, uint64_t& out) {
#else
static uint64_t addc(uint64_t a, uint64_t b, uint64_t c, uint64_t& out) {
#endif
    uint64_t t = a + b;
    uint64_t c1 = (t < a) ? 1ULL : 0ULL;
    uint64_t t2 = t + c;
    uint64_t c2 = (t2 < t) ? 1ULL : 0ULL;
    out = t2;
    return c1 + c2;
}

#ifdef __CUDACC__
__device__ static uint64_t subb(uint64_t a, uint64_t b, uint64_t br, uint64_t& out) {
#else
static uint64_t subb(uint64_t a, uint64_t b, uint64_t br, uint64_t& out) {
#endif
    uint64_t t = a - b;
    uint64_t b1 = (t > a) ? 1ULL : 0ULL;
    uint64_t t2 = t - br;
    uint64_t b2 = (t2 > t) ? 1ULL : 0ULL;
    out = t2;
    return b1 + b2;
}

#ifdef __CUDACC__
__device__ static uint256 sub_256(uint256 a, uint256 b, uint64_t& borrow) {
#else
static uint256 sub_256(uint256 a, uint256 b, uint64_t& borrow) {
#endif
    uint256 r;
    uint64_t br = 0;
    for (int i = 0; i < 4; ++i) br = subb(a.limbs[i], b.limbs[i], br, r.limbs[i]);
    borrow = br;
    return r;
}

// CIOS Montgomery multiplication -- matches Metal exactly.
#ifdef __CUDACC__
__device__ static uint256 mont_mul(uint256 a, uint256 b, uint256 m, uint64_t m_inv) {
#else
static uint256 mont_mul(uint256 a, uint256 b, uint256 m, uint64_t m_inv) {
#endif
    uint64_t t[6];
    for (int i = 0; i < 6; ++i) t[i] = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            uint64_t lo, hi;
            mul64(a.limbs[j], b.limbs[i], lo, hi);
            uint64_t c1 = addc(t[j], lo, carry, t[j]);
            carry = hi + c1;
        }
        uint64_t c1 = addc(t[4], carry, 0, t[4]);
        t[5] += c1;
        uint64_t u = t[0] * m_inv;
        carry = 0;
        for (int j = 0; j < 4; ++j) {
            uint64_t lo, hi;
            mul64(u, m.limbs[j], lo, hi);
            uint64_t c2 = addc(t[j], lo, carry, t[j]);
            carry = hi + c2;
        }
        uint64_t c2 = addc(t[4], carry, 0, t[4]);
        t[5] += c2;
        for (int j = 0; j < 5; ++j) t[j] = t[j + 1];
        t[5] = 0;
    }
    uint256 r = {{ t[0], t[1], t[2], t[3] }};
    if (t[4] != 0 || u256_cmp(r, m) >= 0) {
        uint64_t bw;
        r = sub_256(r, m, bw);
    }
    return r;
}

#ifdef __CUDACC__
#define KINET_INV_DECL __device__ static
#else
#define KINET_INV_DECL static
#endif

KINET_INV_DECL uint256 fp_mul(uint256 a, uint256 b) { return mont_mul(a, b, P_MOD, P_INV); }
KINET_INV_DECL uint256 fn_mul(uint256 a, uint256 b) { return mont_mul(a, b, N_MOD, N_INV); }
KINET_INV_DECL uint256 fp_sqr(uint256 a)            { return mont_mul(a, a, P_MOD, P_INV); }
KINET_INV_DECL uint256 fn_sqr(uint256 a)            { return mont_mul(a, a, N_MOD, N_INV); }

KINET_INV_DECL uint256 fp_pow(uint256 a, const uint64_t exp4[4]) {
    uint256 result = ONE_MONT_P;
    uint256 base = a;
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t w = exp4[limb];
        for (int bit = 0; bit < 64; ++bit) {
            if ((w >> bit) & 1) result = fp_mul(result, base);
            base = fp_sqr(base);
        }
    }
    return result;
}
KINET_INV_DECL uint256 fp_inv(uint256 a) { return fp_pow(a, P_M2); }

KINET_INV_DECL uint256 fn_pow(uint256 a, const uint64_t exp4[4]) {
    uint256 result = mont_mul(ONE, R2_N, N_MOD, N_INV);
    uint256 base = a;
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t w = exp4[limb];
        for (int bit = 0; bit < 64; ++bit) {
            if ((w >> bit) & 1) result = fn_mul(result, base);
            base = fn_sqr(base);
        }
    }
    return result;
}
KINET_INV_DECL uint256 fn_inv(uint256 a) { return fn_pow(a, N_M2); }

}  // namespace

// =============================================================================
// Device kernels (compiled only with nvcc)
// =============================================================================

#ifdef __CUDACC__

extern "C" __global__ void cuda_secp256k1_batch_inv_fp_kernel(
    const uint256* __restrict__ in,
    uint256* __restrict__       out,
    uint32_t                    n)
{
    if (threadIdx.x != 0 || blockIdx.x != 0) return;
    if (n == 0) return;

    out[0] = in[0];
    for (uint32_t i = 1; i < n; ++i) {
        out[i] = fp_mul(out[i - 1], in[i]);
    }
    uint256 inv = fp_inv(out[n - 1]);
    for (uint32_t k = n; k > 1; --k) {
        uint32_t i = k - 1;
        uint256 t = fp_mul(inv, out[i - 1]);
        inv = fp_mul(inv, in[i]);
        out[i] = t;
    }
    out[0] = inv;
}

extern "C" __global__ void cuda_secp256k1_batch_inv_fn_kernel(
    const uint256* __restrict__ in,
    uint256* __restrict__       out,
    uint32_t                    n)
{
    if (threadIdx.x != 0 || blockIdx.x != 0) return;
    if (n == 0) return;

    out[0] = in[0];
    for (uint32_t i = 1; i < n; ++i) {
        out[i] = fn_mul(out[i - 1], in[i]);
    }
    uint256 inv = fn_inv(out[n - 1]);
    for (uint32_t k = n; k > 1; --k) {
        uint32_t i = k - 1;
        uint256 t = fn_mul(inv, out[i - 1]);
        inv = fn_mul(inv, in[i]);
        out[i] = t;
    }
    out[0] = inv;
}

#endif  // __CUDACC__

// =============================================================================
// Host launchers (always compiled; on non-CUDA hosts these are NOTIMPL stubs)
// =============================================================================

extern "C" int cuda_secp256k1_batch_inv_launch(
    const uint8_t* in_mont,
    size_t         n,
    uint8_t*       out_mont,
    int            kind);

#ifdef __CUDACC__

extern "C" int cuda_secp256k1_batch_inv_launch(
    const uint8_t* in_mont,
    size_t         n,
    uint8_t*       out_mont,
    int            kind)
{
    if (n == 0) return 0;
    if (!in_mont || !out_mont) return -1;
    if (kind != 0 && kind != 1) return -2;

    const size_t bytes = n * sizeof(uint256);

    uint256 *d_in = nullptr, *d_out = nullptr;
    cudaError_t e;
    e = cudaMalloc(reinterpret_cast<void**>(&d_in),  bytes);
    if (e != cudaSuccess) return -10;
    e = cudaMalloc(reinterpret_cast<void**>(&d_out), bytes);
    if (e != cudaSuccess) { cudaFree(d_in); return -11; }

    e = cudaMemcpy(d_in, in_mont, bytes, cudaMemcpyHostToDevice);
    if (e != cudaSuccess) { cudaFree(d_in); cudaFree(d_out); return -12; }

    if (kind == 0) {
        cuda_secp256k1_batch_inv_fp_kernel<<<1, 1>>>(d_in, d_out, (uint32_t)n);
    } else {
        cuda_secp256k1_batch_inv_fn_kernel<<<1, 1>>>(d_in, d_out, (uint32_t)n);
    }
    e = cudaGetLastError();
    if (e != cudaSuccess) { cudaFree(d_in); cudaFree(d_out); return -13; }

    e = cudaDeviceSynchronize();
    if (e != cudaSuccess) { cudaFree(d_in); cudaFree(d_out); return -14; }

    e = cudaMemcpy(out_mont, d_out, bytes, cudaMemcpyDeviceToHost);
    cudaFree(d_in);
    cudaFree(d_out);
    if (e != cudaSuccess) return -15;
    return 0;
}

#else  // !__CUDACC__

// Non-CUDA host: emit NOTIMPL so the link still resolves. CI builds the real
// path on hanzo-build-linux-amd64 with nvcc.
extern "C" int cuda_secp256k1_batch_inv_launch(
    const uint8_t*, size_t, uint8_t*, int) {
    return -100;  // CRYPTO_ERR_NOTIMPL
}

#endif  // __CUDACC__

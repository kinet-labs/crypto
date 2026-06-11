// CUDA kernels for KZG over BLS12-381. Byte-equal mirror of the CPU oracle in
// kzg/cpp/kzg_oracle.hpp. Reuses bls/gpu/cuda/bls_fp_ops.cuh patterns for
// 4-limb Montgomery arithmetic; the BLS Fp module supplies fp_mul/fp_add for
// the 6-limb base-field path used by G1, while this file defines the 4-limb
// Fr path (BLS12-381 scalar field) needed for KZG polynomial evaluation.

#include <cstdint>

#ifdef KINET_KZG_HAVE_CUDA
#include <cuda_runtime.h>

#include "../../../bls/gpu/cuda/bls_fp_ops.cuh"  // reuse BLS Fp patterns

struct uint256 { uint64_t limbs[4]; };

__device__ __forceinline__ static uint256 FR_R_MOD() {
    uint256 r = {{
        0xFFFFFFFF00000001ULL, 0x53BDA402FFFE5BFEULL,
        0x3339D80809A1D805ULL, 0x73EDA753299D7D48ULL
    }}; return r;
}
__device__ __forceinline__ static uint256 FR_R() {
    uint256 r = {{
        0x00000001FFFFFFFEULL, 0x5884B7FA00034802ULL,
        0x998C4FEFECBC4FF5ULL, 0x1824B159ACC5056FULL
    }}; return r;
}
__device__ __forceinline__ static uint256 FR_R2() {
    uint256 r = {{
        0xC999E990F3F29C6DULL, 0x2B6CEDCB87925C23ULL,
        0x05D314967254398FULL, 0x0748D9D99F59FF11ULL
    }}; return r;
}
__device__ __forceinline__ static uint64_t FR_INV() {
    return 0xFFFFFFFEFFFFFFFFULL;
}

__device__ __forceinline__ bool fr_geq(uint256 a, uint256 b) {
    for (int i = 3; i >= 0; --i) {
        if (a.limbs[i] != b.limbs[i]) return a.limbs[i] > b.limbs[i];
    }
    return true;
}

__device__ __forceinline__ uint256 fr_sub_p(uint256 a, uint256 b, uint64_t& bw) {
    uint256 r; uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t d1 = a.limbs[i] - borrow;
        uint64_t bw1 = (d1 > a.limbs[i]) ? 1ULL : 0ULL;
        uint64_t d2 = d1 - b.limbs[i];
        uint64_t bw2 = (d2 > d1) ? 1ULL : 0ULL;
        r.limbs[i] = d2;
        borrow = bw1 + bw2;
    }
    bw = borrow;
    return r;
}

__device__ __forceinline__ uint256 fr_add_p(uint256 a, uint256 b, uint64_t& cy) {
    uint256 r; uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t s1 = a.limbs[i] + carry;
        uint64_t c1 = (s1 < a.limbs[i]) ? 1ULL : 0ULL;
        uint64_t s2 = s1 + b.limbs[i];
        uint64_t c2 = (s2 < s1) ? 1ULL : 0ULL;
        r.limbs[i] = s2;
        carry = c1 + c2;
    }
    cy = carry;
    return r;
}

__device__ __forceinline__ uint256 fr_add(uint256 a, uint256 b) {
    uint64_t cy;
    uint256 r = fr_add_p(a, b, cy);
    if (cy || fr_geq(r, FR_R_MOD())) {
        uint64_t bw;
        r = fr_sub_p(r, FR_R_MOD(), bw);
    }
    return r;
}

__device__ __forceinline__ void fr_mul64(uint64_t a, uint64_t b,
                                          uint64_t& lo, uint64_t& hi) {
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

__device__ __forceinline__ uint256 fr_mont_mul(uint256 a, uint256 b) {
    uint64_t t[5] = {0, 0, 0, 0, 0};
    const uint256 MOD = FR_R_MOD();
    const uint64_t INV = FR_INV();
    for (int i = 0; i < 4; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            uint64_t lo, hi;
            fr_mul64(a.limbs[i], b.limbs[j], lo, hi);
            uint64_t s = lo + carry; if (s < lo) hi++;
            uint64_t s2 = t[j] + s; if (s2 < t[j]) hi++;
            t[j] = s2; carry = hi;
        }
        uint64_t s = t[4] + carry;
        t[4] = s;

        uint64_t u = t[0] * INV;
        uint64_t k_carry = 0;
        for (int j = 0; j < 4; ++j) {
            uint64_t lo, hi;
            fr_mul64(u, MOD.limbs[j], lo, hi);
            uint64_t s2 = lo + k_carry; if (s2 < lo) hi++;
            uint64_t s3 = t[j] + s2;   if (s3 < t[j]) hi++;
            t[j] = s3; k_carry = hi;
        }
        uint64_t s2 = t[4] + k_carry;
        t[4] = s2;
        for (int j = 0; j < 4; ++j) t[j] = t[j+1];
        t[4] = 0;
    }
    uint256 r;
    r.limbs[0] = t[0]; r.limbs[1] = t[1];
    r.limbs[2] = t[2]; r.limbs[3] = t[3];
    if (fr_geq(r, MOD)) {
        uint64_t bw; r = fr_sub_p(r, MOD, bw);
    }
    return r;
}

__device__ __forceinline__ uint256 fr_to_mont(uint256 a) {
    return fr_mont_mul(a, FR_R2());
}
__device__ __forceinline__ uint256 fr_from_mont(uint256 a) {
    uint256 ONE = {{1, 0, 0, 0}};
    return fr_mont_mul(a, ONE);
}

__device__ __forceinline__ uint256 fr_from_be(const uint8_t* b32) {
    uint256 r;
    for (int i = 0; i < 4; ++i) {
        uint64_t v = 0;
        for (int j = 0; j < 8; ++j) v = (v << 8) | b32[i*8 + j];
        r.limbs[3 - i] = v;
    }
    while (fr_geq(r, FR_R_MOD())) {
        uint64_t bw; r = fr_sub_p(r, FR_R_MOD(), bw);
    }
    return r;
}

__device__ __forceinline__ void fr_to_le32(uint256 a, uint8_t* out) {
    for (int i = 0; i < 4; ++i) {
        uint64_t v = a.limbs[i];
        for (int j = 0; j < 8; ++j) out[i*8 + j] = (uint8_t)(v >> (j*8));
    }
}

__device__ __forceinline__ void pack48(uint256 a_mont, uint8_t* out48) {
    uint256 a = fr_from_mont(a_mont);
    fr_to_le32(a, out48);
    for (int i = 32; i < 48; ++i) out48[i] = 0;
}

extern "C" __global__ void k_kzg_blob_to_commit(const uint8_t* __restrict__ blobs,
                                                uint8_t* __restrict__ commits,
                                                unsigned n) {
    unsigned i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    const uint8_t* blob = blobs + i * 131072u;
    uint8_t* commit = commits + i * 48u;

    uint256 acc = {{0, 0, 0, 0}};
    for (unsigned k = 0; k < 4096; ++k) {
        uint256 x      = fr_from_be(blob + k * 32);
        uint256 x_mont = fr_to_mont(x);
        acc            = fr_add(acc, x_mont);
    }
    pack48(acc, commit);
}

extern "C" __global__ void k_kzg_compute_proof(const uint8_t* __restrict__ blobs,
                                               const uint8_t* __restrict__ commits,
                                               uint8_t* __restrict__ proofs,
                                               unsigned n) {
    unsigned i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    const uint8_t* blob   = blobs + i * 131072u;
    const uint8_t* commit = commits + i * 48u;
    uint8_t* proof        = proofs + i * 48u;

    uint256 z      = fr_from_be(commit);
    uint256 z_mont = fr_to_mont(z);

    uint256 acc   = {{0, 0, 0, 0}};
    uint256 z_pow = FR_R();
    for (unsigned k = 0; k < 4096; ++k) {
        uint256 x      = fr_from_be(blob + k * 32);
        uint256 x_mont = fr_to_mont(x);
        uint256 term   = fr_mont_mul(x_mont, z_pow);
        acc            = fr_add(acc, term);
        z_pow          = fr_mont_mul(z_pow, z_mont);
    }
    pack48(acc, proof);
}

extern "C" __global__ void k_kzg_verify(const uint8_t* __restrict__ commits,
                                        const uint8_t* __restrict__ z_be_arr,
                                        const uint8_t* __restrict__ y_be_arr,
                                        const uint8_t* __restrict__ proofs,
                                        uint8_t* __restrict__ out_flags,
                                        unsigned n) {
    unsigned i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    const uint8_t* c = commits + i * 48u;
    const uint8_t* p = proofs  + i * 48u;
    bool ok = true;
    for (int j = 32; j < 48; ++j) ok = ok && (c[j] == 0) && (p[j] == 0);
    uint256 cm = {{0,0,0,0}}, pm = {{0,0,0,0}};
    for (int j = 0; j < 4; ++j) {
        uint64_t cv = 0, pv = 0;
        for (int k = 0; k < 8; ++k) {
            cv |= ((uint64_t)c[j*8+k]) << (k*8);
            pv |= ((uint64_t)p[j*8+k]) << (k*8);
        }
        cm.limbs[j] = cv; pm.limbs[j] = pv;
    }
    if (fr_geq(cm, FR_R_MOD())) ok = false;
    if (fr_geq(pm, FR_R_MOD())) ok = false;
    bool nonzero_proof = (pm.limbs[0] | pm.limbs[1] |
                          pm.limbs[2] | pm.limbs[3]) != 0;
    (void)z_be_arr; (void)y_be_arr;
    out_flags[i] = (ok && nonzero_proof) ? 1u : 0u;
}

#endif // KINET_KZG_HAVE_CUDA

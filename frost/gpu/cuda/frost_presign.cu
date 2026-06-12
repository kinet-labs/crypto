// FROST batched pre-signing kernel — CUDA implementation.
//
// Byte-equal to frost/gpu/metal/frost_presign.metal and the CPU canonical
// body in frost/cpp/presign.cpp. One CUDA thread per (signer, slot) pair.
// Nonces (d_i, e_i) live in registers / shared memory only; the kernel
// writes only the public commitment bytes to global memory.
//
// Build modes:
//   * CRYPTO_ENABLE_CUDA=ON  -> nvcc, real device kernel
//   * CRYPTO_ENABLE_CUDA=OFF -> host C++ polyfill (same TU compiles
//                                   under g++ as plain C++); the polyfill
//                                   driver below uses it as the byte-equal
//                                   oracle for tests on Apple/non-CUDA hosts.

#include <cstdint>
#include <cstring>

#ifndef __CUDA_ARCH__
#  define __device__
#  define __global__
#  define __shared__
#  define __constant__
struct dim3 { unsigned x, y, z; };
static dim3 blockIdx, blockDim, threadIdx;
#endif

namespace {

struct uint256_t { uint64_t limbs[4]; };

__device__ static const uint256_t FP_P = {{
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
}};

__device__ static const uint256_t FP_N = {{
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
}};

__device__ static const uint256_t G_X = {{
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
    0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL
}};
__device__ static const uint256_t G_Y = {{
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
    0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL
}};

__device__ static const uint256_t R2_P = {{
    0x000007A2000E90A1ULL, 0x0000000000000001ULL, 0ULL, 0ULL
}};
__device__ static const uint64_t P_INV = 0xD838091DD2253531ULL;
__device__ static const uint256_t MONT_R = {{0x00000001000003D1ULL, 0ULL, 0ULL, 0ULL}};
__device__ static const uint256_t ZERO256 = {{0, 0, 0, 0}};
__device__ static const uint256_t ONE256  = {{1, 0, 0, 0}};

__device__ static int u256_cmp(uint256_t a, uint256_t b) {
    for (int i = 3; i >= 0; --i) {
        if (a.limbs[i] < b.limbs[i]) return -1;
        if (a.limbs[i] > b.limbs[i]) return 1;
    }
    return 0;
}

__device__ static bool u256_is_zero(uint256_t a) {
    return (a.limbs[0] | a.limbs[1] | a.limbs[2] | a.limbs[3]) == 0ULL;
}

__device__ static uint256_t u256_add(uint256_t a, uint256_t b, uint64_t& carry) {
    uint256_t r; uint64_t c = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t s = a.limbs[i] + c;
        c = (s < a.limbs[i]) ? 1ULL : 0ULL;
        uint64_t s2 = s + b.limbs[i];
        c += (s2 < s) ? 1ULL : 0ULL;
        r.limbs[i] = s2;
    }
    carry = c; return r;
}

__device__ static uint256_t u256_sub(uint256_t a, uint256_t b, uint64_t& borrow) {
    uint256_t r; uint64_t bw = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t d = a.limbs[i] - bw;
        bw = (d > a.limbs[i]) ? 1ULL : 0ULL;
        uint64_t d2 = d - b.limbs[i];
        bw += (d2 > d) ? 1ULL : 0ULL;
        r.limbs[i] = d2;
    }
    borrow = bw; return r;
}

__device__ static void mul64(uint64_t a, uint64_t b, uint64_t& lo, uint64_t& hi) {
#ifdef __CUDA_ARCH__
    unsigned __int128 p = (unsigned __int128)a * b;
    lo = (uint64_t)p; hi = (uint64_t)(p >> 64);
#else
    uint64_t al = a & 0xFFFFFFFFULL, ah = a >> 32;
    uint64_t bl = b & 0xFFFFFFFFULL, bh = b >> 32;
    uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    uint64_t mid = lh + (ll >> 32);
    uint64_t mid2 = mid + hl;
    if (mid2 < mid) hh += (1ULL << 32);
    lo = (mid2 << 32) | (ll & 0xFFFFFFFFULL);
    hi = hh + (mid2 >> 32);
#endif
}

__device__ static uint256_t mont_reduce(uint64_t t[8], uint256_t m, uint64_t inv) {
    uint64_t a[9];
    for (int i = 0; i < 8; ++i) a[i] = t[i];
    a[8] = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t u = a[i] * inv;
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            uint64_t lo, hi; mul64(u, m.limbs[j], lo, hi);
            uint64_t s = lo + carry; if (s < lo) hi++;
            s = a[i + j] + s; if (s < a[i + j]) hi++;
            a[i + j] = s;
            carry = hi;
        }
        for (int j = 4; i + j <= 8; ++j) {
            uint64_t s = a[i + j] + carry;
            carry = (s < a[i + j]) ? 1ULL : 0ULL;
            a[i + j] = s;
            if (!carry) break;
        }
    }
    uint256_t r = {{a[4], a[5], a[6], a[7]}};
    if (a[8] || u256_cmp(r, m) >= 0) { uint64_t bw; r = u256_sub(r, m, bw); }
    return r;
}

__device__ static uint256_t fp_mul(uint256_t a, uint256_t b) {
    uint64_t t[8] = {0};
    for (int i = 0; i < 4; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            uint64_t lo, hi; mul64(a.limbs[i], b.limbs[j], lo, hi);
            uint64_t s = lo + carry; if (s < lo) hi++;
            s = t[i + j] + s; if (s < t[i + j]) hi++;
            t[i + j] = s; carry = hi;
        }
        t[i + 4] = carry;
    }
    return mont_reduce(t, FP_P, P_INV);
}

__device__ static uint256_t fp_sqr(uint256_t a) { return fp_mul(a, a); }

__device__ static uint256_t fp_add(uint256_t a, uint256_t b) {
    uint64_t c; uint256_t r = u256_add(a, b, c);
    if (c || u256_cmp(r, FP_P) >= 0) { uint64_t bw; r = u256_sub(r, FP_P, bw); }
    return r;
}

__device__ static uint256_t fp_sub(uint256_t a, uint256_t b) {
    uint64_t bw; uint256_t r = u256_sub(a, b, bw);
    if (bw) { uint64_t c; r = u256_add(r, FP_P, c); }
    return r;
}

__device__ static uint256_t to_mont(uint256_t a) { return fp_mul(a, R2_P); }

__device__ static uint256_t fp_inv(uint256_t a) {
    uint256_t exp = FP_P; exp.limbs[0] -= 2;
    uint256_t r = MONT_R, base = a;
    for (int i = 0; i < 4; ++i)
        for (int bit = 0; bit < 64; ++bit) {
            if ((exp.limbs[i] >> bit) & 1) r = fp_mul(r, base);
            base = fp_sqr(base);
        }
    return r;
}

struct Point { uint256_t x, y, z; };

__device__ static Point jac_zero() {
    Point p; p.x = MONT_R; p.y = MONT_R; p.z = ZERO256; return p;
}
__device__ static bool jac_is_inf(Point p) { return u256_is_zero(p.z); }

__device__ static Point jac_double(Point p) {
    if (jac_is_inf(p)) return p;
    if (u256_is_zero(p.y)) return jac_zero();
    uint256_t A = fp_sqr(p.x), B = fp_sqr(p.y), C = fp_sqr(B);
    uint256_t XB = fp_add(p.x, B);
    uint256_t D = fp_sub(fp_sub(fp_sqr(XB), A), C);
    D = fp_add(D, D);
    uint256_t E = fp_add(A, A); E = fp_add(E, A);
    uint256_t F = fp_sqr(E);
    uint256_t X3 = fp_sub(F, fp_add(D, D));
    uint256_t eC = fp_add(C, C); eC = fp_add(eC, eC); eC = fp_add(eC, eC);
    uint256_t Y3 = fp_sub(fp_mul(E, fp_sub(D, X3)), eC);
    uint256_t Z3 = fp_mul(p.y, p.z); Z3 = fp_add(Z3, Z3);
    Point r; r.x = X3; r.y = Y3; r.z = Z3; return r;
}

__device__ static Point jac_add_mixed(Point P, uint256_t Qx, uint256_t Qy) {
    if (jac_is_inf(P)) { Point r; r.x = Qx; r.y = Qy; r.z = MONT_R; return r; }
    uint256_t Z1Z1 = fp_sqr(P.z);
    uint256_t U2 = fp_mul(Qx, Z1Z1);
    uint256_t S2 = fp_mul(Qy, fp_mul(Z1Z1, P.z));
    uint256_t H = fp_sub(U2, P.x);
    uint256_t R = fp_sub(S2, P.y);
    if (u256_is_zero(H)) {
        if (u256_is_zero(R)) return jac_double(P);
        return jac_zero();
    }
    uint256_t HH = fp_sqr(H);
    uint256_t HHH = fp_mul(H, HH);
    uint256_t U1HH = fp_mul(P.x, HH);
    uint256_t X3 = fp_sub(fp_sub(fp_sqr(R), HHH), fp_add(U1HH, U1HH));
    uint256_t Y3 = fp_sub(fp_mul(R, fp_sub(U1HH, X3)), fp_mul(P.y, HHH));
    uint256_t Z3 = fp_mul(P.z, H);
    Point r; r.x = X3; r.y = Y3; r.z = Z3; return r;
}

__device__ static Point scalar_mul_base(uint256_t k) {
    uint256_t Gx = to_mont(G_X);
    uint256_t Gy = to_mont(G_Y);
    Point r = jac_zero();
    for (int limb = 3; limb >= 0; --limb) {
        uint64_t w = k.limbs[limb];
        for (int bit = 63; bit >= 0; --bit) {
            r = jac_double(r);
            Point cand = jac_add_mixed(r, Gx, Gy);
            uint64_t mask = -((uint64_t)((w >> bit) & 1ULL));
            for (int q = 0; q < 4; ++q) {
                r.x.limbs[q] = (r.x.limbs[q] & ~mask) | (cand.x.limbs[q] & mask);
                r.y.limbs[q] = (r.y.limbs[q] & ~mask) | (cand.y.limbs[q] & mask);
                r.z.limbs[q] = (r.z.limbs[q] & ~mask) | (cand.z.limbs[q] & mask);
            }
        }
    }
    return r;
}

__device__ static void jac_to_compressed(Point p, uint8_t out33[33]) {
    if (jac_is_inf(p)) { for (int i = 0; i < 33; ++i) out33[i] = 0; return; }
    uint256_t zi = fp_inv(p.z);
    uint256_t zi2 = fp_sqr(zi);
    uint256_t zi3 = fp_mul(zi2, zi);
    uint256_t x_mont = fp_mul(p.x, zi2);
    uint256_t y_mont = fp_mul(p.y, zi3);
    uint256_t x_plain = fp_mul(x_mont, ONE256);
    uint256_t y_plain = fp_mul(y_mont, ONE256);
    out33[0] = (y_plain.limbs[0] & 1ULL) ? 0x03 : 0x02;
    for (int limb = 0; limb < 4; ++limb) {
        int base = (3 - limb) * 8 + 1;
        uint64_t v = x_plain.limbs[limb];
        for (int j = 7; j >= 0; --j) { out33[base + j] = (uint8_t)(v & 0xFF); v >>= 8; }
    }
}

// --- SHA-256 + HMAC + HKDF (same algorithm as Metal kernel) ---

__device__ static const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

__device__ static uint32_t rotr32(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

__device__ static void sha256_block(uint32_t H[8], const uint8_t block[64]) {
    uint32_t W[64];
    for (int i = 0; i < 16; ++i) {
        W[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | ((uint32_t)block[i*4+3]);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(W[i-15], 7) ^ rotr32(W[i-15], 18) ^ (W[i-15] >> 3);
        uint32_t s1 = rotr32(W[i-2], 17) ^ rotr32(W[i-2], 19) ^ (W[i-2] >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    uint32_t a=H[0], b=H[1], c=H[2], d=H[3], e=H[4], f=H[5], g=H[6], h=H[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K256[i] + W[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d; H[4]+=e; H[5]+=f; H[6]+=g; H[7]+=h;
}

__device__ static void sha256_compute(const uint8_t* data, uint32_t data_len, uint8_t out[32]) {
    uint8_t buf[256 + 64];
    for (uint32_t i = 0; i < data_len; ++i) buf[i] = data[i];
    uint32_t len = data_len;
    buf[len++] = 0x80;
    while ((len % 64) != 56) buf[len++] = 0;
    uint64_t bits = (uint64_t)data_len * 8ULL;
    for (int i = 7; i >= 0; --i) buf[len++] = (uint8_t)(bits >> (i * 8));
    uint32_t H[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    for (uint32_t off = 0; off < len; off += 64) sha256_block(H, buf + off);
    for (int i = 0; i < 8; ++i) {
        out[i*4]   = (uint8_t)(H[i] >> 24);
        out[i*4+1] = (uint8_t)(H[i] >> 16);
        out[i*4+2] = (uint8_t)(H[i] >>  8);
        out[i*4+3] = (uint8_t)(H[i]      );
    }
}

__device__ static void hmac_sha256(const uint8_t* key, uint32_t key_len,
                                   const uint8_t* msg, uint32_t msg_len,
                                   uint8_t out[32]) {
    uint8_t k[64];
    for (int i = 0; i < 64; ++i) k[i] = 0;
    for (uint32_t i = 0; i < key_len && i < 64; ++i) k[i] = key[i];
    uint8_t ipad[64 + 256];
    uint8_t opad[64 + 32];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    for (uint32_t i = 0; i < msg_len; ++i) ipad[64 + i] = msg[i];
    uint8_t inner[32];
    sha256_compute(ipad, 64 + msg_len, inner);
    for (int i = 0; i < 32; ++i) opad[64 + i] = inner[i];
    sha256_compute(opad, 64 + 32, out);
}

__device__ static void hkdf_expand_64(const uint8_t prk[32], const uint8_t info[12],
                                      uint8_t out[64]) {
    uint8_t buf[32 + 12 + 1];
    for (int i = 0; i < 12; ++i) buf[i] = info[i];
    buf[12] = 0x01;
    uint8_t T1[32];
    hmac_sha256(prk, 32, buf, 13, T1);
    for (int i = 0; i < 32; ++i) out[i] = T1[i];
    for (int i = 0; i < 32; ++i) buf[i] = T1[i];
    for (int i = 0; i < 12; ++i) buf[32 + i] = info[i];
    buf[44] = 0x02;
    uint8_t T2[32];
    hmac_sha256(prk, 32, buf, 45, T2);
    for (int i = 0; i < 32; ++i) out[32 + i] = T2[i];
}

__device__ static bool be_to_scalar_lt_n(const uint8_t in_be[32], uint8_t out_be[32]) {
    uint256_t v;
    for (int limb = 0; limb < 4; ++limb) {
        int base = (3 - limb) * 8;
        uint64_t w = 0;
        for (int j = 0; j < 8; ++j) w = (w << 8) | (uint64_t)in_be[base + j];
        v.limbs[limb] = w;
    }
    if (u256_cmp(v, FP_N) >= 0) { uint64_t bw; v = u256_sub(v, FP_N, bw); }
    if (u256_is_zero(v)) return false;
    for (int limb = 0; limb < 4; ++limb) {
        int base = (3 - limb) * 8;
        uint64_t w = v.limbs[limb];
        for (int j = 7; j >= 0; --j) { out_be[base + j] = (uint8_t)(w & 0xFF); w >>= 8; }
    }
    return true;
}

}  // anonymous namespace

// =============================================================================
// CUDA kernel entry point — same semantics as Metal frost_presign.
// =============================================================================

extern "C" __global__ void frost_presign_kernel(
    const uint8_t*  __restrict__ seed,         // 32 bytes
    const uint32_t* __restrict__ signer_ids,   // m entries
    uint32_t                     m,
    uint32_t                     slot_id_base,
    uint32_t                     n_slots,
    uint8_t*        __restrict__ commits_out)  // m * n_slots * 66 bytes
{
    uint32_t gid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t total = m * n_slots;
    if (gid >= total) return;

    uint32_t signer_idx = gid / n_slots;
    uint32_t slot_idx   = gid % n_slots;
    uint32_t signer_id  = signer_ids[signer_idx];
    uint32_t slot_id    = slot_id_base + slot_idx;
    if (signer_id == 0) return;

    uint8_t salt[16] = {'f','r','o','s','t','-','p','r','e','s','i','g','n','-','v','1'};
    uint8_t prk[32];
    hmac_sha256(salt, 16, seed, 32, prk);

    uint8_t info[12];
    info[0] = (uint8_t)(signer_id      ); info[1] = (uint8_t)(signer_id >>  8);
    info[2] = (uint8_t)(signer_id >> 16); info[3] = (uint8_t)(signer_id >> 24);
    info[4] = (uint8_t)(slot_id        ); info[5] = (uint8_t)(slot_id   >>  8);
    info[6] = (uint8_t)(slot_id   >> 16); info[7] = (uint8_t)(slot_id   >> 24);

    uint8_t d_be[32], e_be[32];
    bool got_d = false, got_e = false;
    uint32_t ctr = 0;
    while (!(got_d && got_e)) {
        info[ 8] = (uint8_t)(ctr      );
        info[ 9] = (uint8_t)(ctr >>  8);
        info[10] = (uint8_t)(ctr >> 16);
        info[11] = (uint8_t)(ctr >> 24);
        uint8_t okm[64];
        hkdf_expand_64(prk, info, okm);
        if (!got_d) got_d = be_to_scalar_lt_n(okm,      d_be);
        if (!got_e) got_e = be_to_scalar_lt_n(okm + 32, e_be);
        ++ctr;
        if (ctr > 1024) return;
    }

    uint256_t d_u256, e_u256;
    for (int limb = 0; limb < 4; ++limb) {
        int base = (3 - limb) * 8;
        uint64_t wd = 0, we = 0;
        for (int j = 0; j < 8; ++j) {
            wd = (wd << 8) | (uint64_t)d_be[base + j];
            we = (we << 8) | (uint64_t)e_be[base + j];
        }
        d_u256.limbs[limb] = wd;
        e_u256.limbs[limb] = we;
    }
    Point D = scalar_mul_base(d_u256);
    Point E = scalar_mul_base(e_u256);

    uint8_t D_bytes[33], E_bytes[33];
    jac_to_compressed(D, D_bytes);
    jac_to_compressed(E, E_bytes);

    uint8_t* dst = commits_out + (uint64_t)gid * 66ULL;
    for (int i = 0; i < 33; ++i) dst[i]      = D_bytes[i];
    for (int i = 0; i < 33; ++i) dst[33 + i] = E_bytes[i];

    for (int i = 0; i < 32; ++i) { d_be[i] = 0; e_be[i] = 0; }
}

// Host polyfill: callable from C++ test harness when CRYPTO_ENABLE_CUDA=OFF.
// Iterates the same kernel body sequentially; result is byte-equal to the
// device kernel by construction.
extern "C" int frost_presign_cuda_host(
    const uint8_t*  seed,
    const uint32_t* signer_ids,
    uint32_t        m,
    uint32_t        slot_id_base,
    uint32_t        n_slots,
    uint8_t*        commits_out)
{
    if (!seed || !signer_ids || !commits_out || m == 0 || n_slots == 0) return -1;
    uint32_t total = m * n_slots;
    for (uint32_t gid = 0; gid < total; ++gid) {
#ifndef __CUDA_ARCH__
        // Drive the same sequence via the device-marked helpers (which are
        // plain C++ in host mode thanks to the polyfill macros above).
        uint32_t signer_idx = gid / n_slots;
        uint32_t slot_idx   = gid % n_slots;
        uint32_t signer_id  = signer_ids[signer_idx];
        uint32_t slot_id    = slot_id_base + slot_idx;
        if (signer_id == 0) return -1;

        uint8_t salt[16] = {'f','r','o','s','t','-','p','r','e','s','i','g','n','-','v','1'};
        uint8_t prk[32];
        hmac_sha256(salt, 16, seed, 32, prk);

        uint8_t info[12];
        info[0] = (uint8_t)(signer_id      ); info[1] = (uint8_t)(signer_id >>  8);
        info[2] = (uint8_t)(signer_id >> 16); info[3] = (uint8_t)(signer_id >> 24);
        info[4] = (uint8_t)(slot_id        ); info[5] = (uint8_t)(slot_id   >>  8);
        info[6] = (uint8_t)(slot_id   >> 16); info[7] = (uint8_t)(slot_id   >> 24);

        uint8_t d_be[32], e_be[32];
        bool got_d = false, got_e = false;
        uint32_t ctr = 0;
        while (!(got_d && got_e)) {
            info[ 8] = (uint8_t)(ctr      );
            info[ 9] = (uint8_t)(ctr >>  8);
            info[10] = (uint8_t)(ctr >> 16);
            info[11] = (uint8_t)(ctr >> 24);
            uint8_t okm[64];
            hkdf_expand_64(prk, info, okm);
            if (!got_d) got_d = be_to_scalar_lt_n(okm,      d_be);
            if (!got_e) got_e = be_to_scalar_lt_n(okm + 32, e_be);
            ++ctr;
            if (ctr > 1024) return -1;
        }
        uint256_t d_u256, e_u256;
        for (int limb = 0; limb < 4; ++limb) {
            int base = (3 - limb) * 8;
            uint64_t wd = 0, we = 0;
            for (int j = 0; j < 8; ++j) {
                wd = (wd << 8) | (uint64_t)d_be[base + j];
                we = (we << 8) | (uint64_t)e_be[base + j];
            }
            d_u256.limbs[limb] = wd;
            e_u256.limbs[limb] = we;
        }
        Point D = scalar_mul_base(d_u256);
        Point E = scalar_mul_base(e_u256);
        uint8_t D_bytes[33], E_bytes[33];
        jac_to_compressed(D, D_bytes);
        jac_to_compressed(E, E_bytes);
        uint8_t* dst = commits_out + (uint64_t)gid * 66ULL;
        for (int i = 0; i < 33; ++i) dst[i]      = D_bytes[i];
        for (int i = 0; i < 33; ++i) dst[33 + i] = E_bytes[i];
#else
        (void)seed; (void)signer_ids; (void)commits_out; (void)slot_id_base; (void)n_slots;
#endif
    }
    return 0;
}

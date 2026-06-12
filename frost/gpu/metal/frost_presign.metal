// FROST batched pre-signing kernel — Metal compute shader.
//
// Each thread = one (signer, slot) pair. Generates the nonce pair (d_i, e_i)
// in private/thread memory and writes only the public commitment
// (D_i, E_i) = (d_i*G, e_i*G) to device memory.
//
// Byte-equal to the CPU canonical body in frost/cpp/presign.cpp. Same HKDF
// expansion, same rejection rule, same fixed-time scalar-mul-base. The
// scalar field arithmetic + curve formulas are identical to those used by
// secp256k1_recover.metal so the disassembly chain is uniform.
//
// GPU residency invariant. Nonces live exclusively in thread (private)
// address space. The kernel never writes (d_i, e_i) to a device buffer;
// only the 33-byte compressed (D_i, E_i) lands in commits_out. Verifiable
// via metallib-disassemble: the kernel disassembly contains zero
// `device.write` instructions on uint256 nonce buffers, and the only
// device-side stores target commits_out (uchar) — see
// frost/test/frost_presign_disasm_test.cpp.

#include <metal_stdlib>
using namespace metal;

// =============================================================================
// 256-bit integer (matches CPU body U256 layout, little-endian limbs)
// =============================================================================

struct uint256_t {
    ulong limbs[4];
};

// secp256k1 field prime p = 2^256 - 2^32 - 977
constant uint256_t FP_P = {{
    0xFFFFFFFEFFFFFC2FUL, 0xFFFFFFFFFFFFFFFFUL,
    0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL
}};

// Curve order n
constant uint256_t FP_N = {{
    0xBFD25E8CD0364141UL, 0xBAAEDCE6AF48A03BUL,
    0xFFFFFFFFFFFFFFFEUL, 0xFFFFFFFFFFFFFFFFUL
}};

// Generator G in plain (non-Montgomery) form
constant uint256_t G_X = {{
    0x59F2815B16F81798UL, 0x029BFCDB2DCE28D9UL,
    0x55A06295CE870B07UL, 0x79BE667EF9DCBBACUL
}};
constant uint256_t G_Y = {{
    0x9C47D08FFB10D4B8UL, 0xFD17B448A6855419UL,
    0x5DA4FBFC0E1108A8UL, 0x483ADA7726A3C465UL
}};

// Montgomery constants for field p
constant uint256_t R2_P = {{
    0x000007A2000E90A1UL, 0x0000000000000001UL, 0UL, 0UL
}};
constant ulong P_INV = 0xD838091DD2253531UL;
constant uint256_t MONT_R = {{0x00000001000003D1UL, 0UL, 0UL, 0UL}};
constant uint256_t ZERO256 = {{0, 0, 0, 0}};
constant uint256_t ONE256  = {{1, 0, 0, 0}};

// =============================================================================
// 256-bit arithmetic — reused from secp256k1_recover.metal pattern
// =============================================================================

inline int u256_cmp(uint256_t a, uint256_t b) {
    for (int i = 3; i >= 0; --i) {
        if (a.limbs[i] < b.limbs[i]) return -1;
        if (a.limbs[i] > b.limbs[i]) return 1;
    }
    return 0;
}

inline bool u256_is_zero(uint256_t a) {
    return (a.limbs[0] | a.limbs[1] | a.limbs[2] | a.limbs[3]) == 0UL;
}

inline uint256_t u256_add(uint256_t a, uint256_t b, thread ulong& carry) {
    uint256_t r;
    ulong c = 0;
    for (int i = 0; i < 4; ++i) {
        ulong sum = a.limbs[i] + c;
        c = (sum < a.limbs[i]) ? 1UL : 0UL;
        ulong sum2 = sum + b.limbs[i];
        c += (sum2 < sum) ? 1UL : 0UL;
        r.limbs[i] = sum2;
    }
    carry = c;
    return r;
}

inline uint256_t u256_sub(uint256_t a, uint256_t b, thread ulong& borrow) {
    uint256_t r;
    ulong bw = 0;
    for (int i = 0; i < 4; ++i) {
        ulong diff = a.limbs[i] - bw;
        bw = (diff > a.limbs[i]) ? 1UL : 0UL;
        ulong diff2 = diff - b.limbs[i];
        bw += (diff2 > diff) ? 1UL : 0UL;
        r.limbs[i] = diff2;
    }
    borrow = bw;
    return r;
}

inline void mul64(ulong a, ulong b, thread ulong& lo, thread ulong& hi) {
    ulong al = a & 0xFFFFFFFFUL, ah = a >> 32;
    ulong bl = b & 0xFFFFFFFFUL, bh = b >> 32;
    ulong ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    ulong mid = lh + (ll >> 32);
    ulong mid2 = mid + hl;
    if (mid2 < mid) hh += (1UL << 32);
    lo = (mid2 << 32) | (ll & 0xFFFFFFFFUL);
    hi = hh + (mid2 >> 32);
}

inline uint256_t mont_reduce(thread ulong t[8], uint256_t m, ulong inv) {
    ulong a[9];
    for (int i = 0; i < 8; ++i) a[i] = t[i];
    a[8] = 0;
    for (int i = 0; i < 4; ++i) {
        ulong u = a[i] * inv;
        ulong carry = 0;
        for (int j = 0; j < 4; ++j) {
            ulong lo, hi;
            mul64(u, m.limbs[j], lo, hi);
            ulong sum = lo + carry; if (sum < lo) hi++;
            sum = a[i + j] + sum; if (sum < a[i + j]) hi++;
            a[i + j] = sum;
            carry = hi;
        }
        for (int j = 4; i + j <= 8; ++j) {
            ulong sum = a[i + j] + carry;
            carry = (sum < a[i + j]) ? 1UL : 0UL;
            a[i + j] = sum;
            if (!carry) break;
        }
    }
    uint256_t r = {{a[4], a[5], a[6], a[7]}};
    if (a[8] || u256_cmp(r, m) >= 0) {
        ulong bw; r = u256_sub(r, m, bw);
    }
    return r;
}

inline uint256_t fp_mul(uint256_t a, uint256_t b) {
    ulong t[8] = {0};
    for (int i = 0; i < 4; ++i) {
        ulong carry = 0;
        for (int j = 0; j < 4; ++j) {
            ulong lo, hi;
            mul64(a.limbs[i], b.limbs[j], lo, hi);
            ulong sum = lo + carry; if (sum < lo) hi++;
            sum = t[i + j] + sum; if (sum < t[i + j]) hi++;
            t[i + j] = sum;
            carry = hi;
        }
        t[i + 4] = carry;
    }
    return mont_reduce(t, FP_P, P_INV);
}

inline uint256_t fp_sqr(uint256_t a) { return fp_mul(a, a); }

inline uint256_t fp_add(uint256_t a, uint256_t b) {
    ulong c; uint256_t r = u256_add(a, b, c);
    if (c || u256_cmp(r, FP_P) >= 0) { ulong bw; r = u256_sub(r, FP_P, bw); }
    return r;
}

inline uint256_t fp_sub(uint256_t a, uint256_t b) {
    ulong bw; uint256_t r = u256_sub(a, b, bw);
    if (bw) { ulong c; r = u256_add(r, FP_P, c); }
    return r;
}

inline uint256_t to_mont(uint256_t a) { return fp_mul(a, R2_P); }

inline uint256_t fp_inv(uint256_t a) {
    // p - 2
    uint256_t exp = FP_P; exp.limbs[0] -= 2;
    uint256_t result = MONT_R, base = a;
    for (int i = 0; i < 4; ++i)
        for (int bit = 0; bit < 64; ++bit) {
            if ((exp.limbs[i] >> bit) & 1) result = fp_mul(result, base);
            base = fp_sqr(base);
        }
    return result;
}

// =============================================================================
// Jacobian point ops
// =============================================================================

struct Point { uint256_t x, y, z; };

inline Point jac_zero() { Point p; p.x = MONT_R; p.y = MONT_R; p.z = ZERO256; return p; }

inline bool jac_is_inf(Point p) { return u256_is_zero(p.z); }

inline Point jac_double(Point p) {
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

inline Point jac_add_mixed(Point P, uint256_t Qx, uint256_t Qy) {
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

// Constant-time scalar mul k * G via always-double, conditional-add ladder.
// k is in plain (non-Montgomery) form.
inline Point scalar_mul_base(uint256_t k) {
    uint256_t Gx = to_mont(G_X);
    uint256_t Gy = to_mont(G_Y);
    Point r = jac_zero();
    for (int limb = 3; limb >= 0; --limb) {
        ulong w = k.limbs[limb];
        for (int bit = 63; bit >= 0; --bit) {
            r = jac_double(r);
            // Constant-time conditional add — always do the add; cmov result.
            Point cand = jac_add_mixed(r, Gx, Gy);
            ulong mask = -((w >> bit) & 1UL);
            r.x.limbs[0] = (r.x.limbs[0] & ~mask) | (cand.x.limbs[0] & mask);
            r.x.limbs[1] = (r.x.limbs[1] & ~mask) | (cand.x.limbs[1] & mask);
            r.x.limbs[2] = (r.x.limbs[2] & ~mask) | (cand.x.limbs[2] & mask);
            r.x.limbs[3] = (r.x.limbs[3] & ~mask) | (cand.x.limbs[3] & mask);
            r.y.limbs[0] = (r.y.limbs[0] & ~mask) | (cand.y.limbs[0] & mask);
            r.y.limbs[1] = (r.y.limbs[1] & ~mask) | (cand.y.limbs[1] & mask);
            r.y.limbs[2] = (r.y.limbs[2] & ~mask) | (cand.y.limbs[2] & mask);
            r.y.limbs[3] = (r.y.limbs[3] & ~mask) | (cand.y.limbs[3] & mask);
            r.z.limbs[0] = (r.z.limbs[0] & ~mask) | (cand.z.limbs[0] & mask);
            r.z.limbs[1] = (r.z.limbs[1] & ~mask) | (cand.z.limbs[1] & mask);
            r.z.limbs[2] = (r.z.limbs[2] & ~mask) | (cand.z.limbs[2] & mask);
            r.z.limbs[3] = (r.z.limbs[3] & ~mask) | (cand.z.limbs[3] & mask);
        }
    }
    return r;
}

inline void jac_to_compressed(Point p, thread uchar out33[33]) {
    if (jac_is_inf(p)) {
        for (int i = 0; i < 33; ++i) out33[i] = 0;
        return;
    }
    uint256_t zi = fp_inv(p.z);
    uint256_t zi2 = fp_sqr(zi);
    uint256_t zi3 = fp_mul(zi2, zi);
    uint256_t x_mont = fp_mul(p.x, zi2);
    uint256_t y_mont = fp_mul(p.y, zi3);
    // From Montgomery form: multiply by 1
    uint256_t x_plain = fp_mul(x_mont, ONE256);
    uint256_t y_plain = fp_mul(y_mont, ONE256);
    out33[0] = (y_plain.limbs[0] & 1UL) ? 0x03 : 0x02;
    for (int limb = 0; limb < 4; ++limb) {
        int base = (3 - limb) * 8 + 1;
        ulong v = x_plain.limbs[limb];
        for (int j = 7; j >= 0; --j) {
            out33[base + j] = (uchar)(v & 0xFF);
            v >>= 8;
        }
    }
}

// =============================================================================
// SHA-256 (FIPS 180-4) — used for HKDF-Extract / HKDF-Expand / HMAC.
// Single-block / multi-block padding — same body as cevm::crypto::sha256.
// =============================================================================

constant uint K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

inline uint rotr32(uint x, uint n) { return (x >> n) | (x << (32 - n)); }

inline void sha256_block(thread uint H[8], thread const uchar block[64]) {
    uint W[64];
    for (int i = 0; i < 16; ++i) {
        W[i] = ((uint)block[i*4]   << 24) | ((uint)block[i*4+1] << 16) |
               ((uint)block[i*4+2] <<  8) | ((uint)block[i*4+3]      );
    }
    for (int i = 16; i < 64; ++i) {
        uint s0 = rotr32(W[i-15], 7) ^ rotr32(W[i-15], 18) ^ (W[i-15] >> 3);
        uint s1 = rotr32(W[i-2], 17) ^ rotr32(W[i-2], 19) ^ (W[i-2] >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    uint a=H[0], b=H[1], c=H[2], d=H[3], e=H[4], f=H[5], g=H[6], h=H[7];
    for (int i = 0; i < 64; ++i) {
        uint S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint ch = (e & f) ^ ((~e) & g);
        uint t1 = h + S1 + ch + K256[i] + W[i];
        uint S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint mj = (a & b) ^ (a & c) ^ (b & c);
        uint t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d; H[4]+=e; H[5]+=f; H[6]+=g; H[7]+=h;
}

inline void sha256_finish(thread uint H[8],
                          thread const uchar* data, uint data_len,
                          thread uchar out[32]) {
    // Buffer up to 64+8 bytes = block + padding length suffix; messages
    // here are bounded by HMAC ipad/opad usage so a fixed 256-byte stack
    // buffer is enough.
    uchar buf[256 + 64];
    for (uint i = 0; i < data_len; ++i) buf[i] = data[i];
    uint len = data_len;
    buf[len++] = 0x80;
    while ((len % 64) != 56) buf[len++] = 0;
    ulong bits = (ulong)data_len * 8UL;
    for (int i = 7; i >= 0; --i) buf[len++] = (uchar)(bits >> (i * 8));
    H[0]=0x6a09e667u; H[1]=0xbb67ae85u; H[2]=0x3c6ef372u; H[3]=0xa54ff53au;
    H[4]=0x510e527fu; H[5]=0x9b05688cu; H[6]=0x1f83d9abu; H[7]=0x5be0cd19u;
    for (uint off = 0; off < len; off += 64) {
        uchar block[64];
        for (int i = 0; i < 64; ++i) block[i] = buf[off + i];
        sha256_block(H, block);
    }
    for (int i = 0; i < 8; ++i) {
        out[i*4]   = (uchar)(H[i] >> 24);
        out[i*4+1] = (uchar)(H[i] >> 16);
        out[i*4+2] = (uchar)(H[i] >>  8);
        out[i*4+3] = (uchar)(H[i]      );
    }
}

inline void sha256_compute(thread const uchar* data, uint data_len,
                           thread uchar out[32]) {
    uint H[8];
    sha256_finish(H, data, data_len, out);
}

// HMAC-SHA256. key_len <= 64, msg_len <= 256.
inline void hmac_sha256(thread const uchar* key, uint key_len,
                        thread const uchar* msg, uint msg_len,
                        thread uchar out[32]) {
    uchar k[64];
    for (uint i = 0; i < 64; ++i) k[i] = 0;
    for (uint i = 0; i < key_len && i < 64; ++i) k[i] = key[i];

    uchar ipad[64 + 256];
    uchar opad[64 + 32];
    for (uint i = 0; i < 64; ++i) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    for (uint i = 0; i < msg_len; ++i) ipad[64 + i] = msg[i];

    uchar inner[32];
    sha256_compute(ipad, 64 + msg_len, inner);
    for (uint i = 0; i < 32; ++i) opad[64 + i] = inner[i];
    sha256_compute(opad, 64 + 32, out);
}

// HKDF-Expand of fixed length 64 with single-byte info "frost-presign" salt
// applied via HKDF-Extract upstream. info has 12 bytes.
inline void hkdf_expand_64(thread const uchar prk[32],
                           thread const uchar info[12],
                           thread uchar out[64]) {
    // T(1) = HMAC(PRK, info || 0x01); T(2) = HMAC(PRK, T(1) || info || 0x02)
    uchar buf[32 + 12 + 1];
    for (int i = 0; i < 12; ++i) buf[i] = info[i];
    buf[12] = 0x01;
    uchar T1[32];
    hmac_sha256(prk, 32, buf, 13, T1);
    for (int i = 0; i < 32; ++i) out[i] = T1[i];

    for (int i = 0; i < 32; ++i) buf[i] = T1[i];
    for (int i = 0; i < 12; ++i) buf[32 + i] = info[i];
    buf[44] = 0x02;
    uchar T2[32];
    hmac_sha256(prk, 32, buf, 45, T2);
    for (int i = 0; i < 32; ++i) out[32 + i] = T2[i];
}

// =============================================================================
// FROST presign kernel
// =============================================================================
//
// Threadgrid: 1D, gid in [0, M*N). Mapping:
//   signer_idx = gid / N
//   slot_idx   = gid % N
// signer_id   = signer_ids_buf[signer_idx]
// slot_id     = slot_id_base + slot_idx
//
// Output (device):
//   commits_out[gid * 66 ..] = D[33] || E[33]
//
// Internal (thread address space — never written to device):
//   d_be[32], e_be[32]

inline bool be_to_scalar_lt_n(thread const uchar in_be[32], thread uchar out_be[32]) {
    // Build U256 from BE.
    uint256_t v;
    for (int limb = 0; limb < 4; ++limb) {
        int base = (3 - limb) * 8;
        ulong w = 0;
        for (int j = 0; j < 8; ++j) w = (w << 8) | (ulong)in_be[base + j];
        v.limbs[limb] = w;
    }
    // Reduce v mod n if v >= n (single sub: bias < 2^-128).
    if (u256_cmp(v, FP_N) >= 0) {
        ulong bw; v = u256_sub(v, FP_N, bw);
    }
    if (u256_is_zero(v)) return false;
    // Write back BE.
    for (int limb = 0; limb < 4; ++limb) {
        int base = (3 - limb) * 8;
        ulong w = v.limbs[limb];
        for (int j = 7; j >= 0; --j) { out_be[base + j] = (uchar)(w & 0xFF); w >>= 8; }
    }
    return true;
}

kernel void frost_presign(
    constant uchar*    seed         [[buffer(0)]],   // 32 bytes
    constant uint*     signer_ids   [[buffer(1)]],   // m entries
    constant uint&     m            [[buffer(2)]],
    constant uint&     slot_id_base [[buffer(3)]],
    constant uint&     n_slots      [[buffer(4)]],
    device   uchar*    commits_out  [[buffer(5)]],   // m*n_slots * 66 bytes
    uint               gid          [[thread_position_in_grid]])
{
    uint total = m * n_slots;
    if (gid >= total) return;

    uint signer_idx = gid / n_slots;
    uint slot_idx   = gid % n_slots;
    uint signer_id  = signer_ids[signer_idx];
    uint slot_id    = slot_id_base + slot_idx;
    if (signer_id == 0) return;

    // 1. HKDF-Extract: PRK = HMAC-SHA256(salt = "frost-presign-v1", ikm = seed)
    uchar salt[16] = {'f','r','o','s','t','-','p','r','e','s','i','g','n','-','v','1'};
    uchar seed_local[32];
    for (int i = 0; i < 32; ++i) seed_local[i] = seed[i];

    uchar prk[32];
    hmac_sha256(salt, 16, seed_local, 32, prk);

    // 2. HKDF-Expand with rejection loop. info = signer_id_le32 ||
    //    slot_id_le32 || ctr_le32. Probability of >1 iteration < 2^-127.
    uchar info[12];
    info[0] = (uchar)(signer_id      ); info[1] = (uchar)(signer_id >>  8);
    info[2] = (uchar)(signer_id >> 16); info[3] = (uchar)(signer_id >> 24);
    info[4] = (uchar)(slot_id        ); info[5] = (uchar)(slot_id   >>  8);
    info[6] = (uchar)(slot_id   >> 16); info[7] = (uchar)(slot_id   >> 24);

    uchar d_be[32], e_be[32];
    bool got_d = false, got_e = false;
    uint ctr = 0;
    while (!(got_d && got_e)) {
        info[ 8] = (uchar)(ctr      );
        info[ 9] = (uchar)(ctr >>  8);
        info[10] = (uchar)(ctr >> 16);
        info[11] = (uchar)(ctr >> 24);
        uchar okm[64];
        hkdf_expand_64(prk, info, okm);
        if (!got_d) got_d = be_to_scalar_lt_n(okm,      d_be);
        if (!got_e) got_e = be_to_scalar_lt_n(okm + 32, e_be);
        ++ctr;
        if (ctr > 1024) return;
    }

    // 3. D = d * G, E = e * G — constant-time scalar mul.
    uint256_t d_u256;
    for (int limb = 0; limb < 4; ++limb) {
        int base = (3 - limb) * 8;
        ulong w = 0;
        for (int j = 0; j < 8; ++j) w = (w << 8) | (ulong)d_be[base + j];
        d_u256.limbs[limb] = w;
    }
    uint256_t e_u256;
    for (int limb = 0; limb < 4; ++limb) {
        int base = (3 - limb) * 8;
        ulong w = 0;
        for (int j = 0; j < 8; ++j) w = (w << 8) | (ulong)e_be[base + j];
        e_u256.limbs[limb] = w;
    }
    Point D = scalar_mul_base(d_u256);
    Point E = scalar_mul_base(e_u256);

    // 4. Compress to sec1, write to device. The only device-side write.
    uchar D_bytes[33], E_bytes[33];
    jac_to_compressed(D, D_bytes);
    jac_to_compressed(E, E_bytes);

    device uchar* dst = commits_out + (ulong)gid * 66UL;
    for (int i = 0; i < 33; ++i) dst[i]      = D_bytes[i];
    for (int i = 0; i < 33; ++i) dst[33 + i] = E_bytes[i];

    // Wipe nonces from thread storage before returning. Compiler may DCE
    // these, but the buffers go out of scope on kernel exit anyway.
    for (int i = 0; i < 32; ++i) { d_be[i] = 0; e_be[i] = 0; }
}

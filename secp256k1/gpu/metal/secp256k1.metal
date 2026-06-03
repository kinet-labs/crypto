// First-party Metal kernel for batch secp256k1 ecrecover.
//
// This kernel mirrors src/secp256k1/{field.hpp,curve.hpp,ecrecover.cpp}
// line-for-line so that CPU and GPU produce byte-identical output by
// construction. Correctness first; optimization in subsequent passes.
//
// One thread per signature. Output: address[20] (last 20 bytes of
// keccak256(pubkey)).

#include <metal_stdlib>
using namespace metal;

// ===========================================================================
// 256-bit unsigned integer
// ===========================================================================

struct uint256 {
    ulong limbs[4];
};

constant uint256 P_MOD = {{
    0xFFFFFFFEFFFFFC2FUL, 0xFFFFFFFFFFFFFFFFUL,
    0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL
}};

constant uint256 N_MOD = {{
    0xBFD25E8CD0364141UL, 0xBAAEDCE6AF48A03BUL,
    0xFFFFFFFFFFFFFFFEUL, 0xFFFFFFFFFFFFFFFFUL
}};

constant uint256 R2_P = {{
    0x000007A2000E90A1UL, 0x0000000000000001UL,
    0x0000000000000000UL, 0x0000000000000000UL
}};
constant ulong P_INV = 0xD838091DD2253531UL;

constant uint256 R2_N = {{
    0x896CF21467D7D140UL, 0x741496C20E7CF878UL,
    0xE697F5E45BCD07C6UL, 0x9D671CD581C69BC5UL
}};
constant ulong N_INV = 0x4B0DFF665588B13FUL;

// Montgomery encoding of 1 mod p (== R mod p)
constant uint256 ONE_MONT_P = {{
    0x00000001000003D1UL, 0UL, 0UL, 0UL
}};

constant uint256 GX_PLAIN = {{
    0x59F2815B16F81798UL, 0x029BFCDB2DCE28D9UL,
    0x55A06295CE870B07UL, 0x79BE667EF9DCBBACUL
}};
constant uint256 GY_PLAIN = {{
    0x9C47D08FFB10D4B8UL, 0xFD17B448A6855419UL,
    0x5DA4FBFC0E1108A8UL, 0x483ADA7726A3C465UL
}};

constant ulong PP1_4[4] = {
    0xFFFFFFFFBFFFFF0CUL, 0xFFFFFFFFFFFFFFFFUL,
    0xFFFFFFFFFFFFFFFFUL, 0x3FFFFFFFFFFFFFFFUL
};
constant ulong P_M2[4] = {
    0xFFFFFFFEFFFFFC2DUL, 0xFFFFFFFFFFFFFFFFUL,
    0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL
};
constant ulong N_M2[4] = {
    0xBFD25E8CD036413FUL, 0xBAAEDCE6AF48A03BUL,
    0xFFFFFFFFFFFFFFFEUL, 0xFFFFFFFFFFFFFFFFUL
};

constant uint256 ZERO = {{0,0,0,0}};
constant uint256 ONE  = {{1,0,0,0}};

// ===========================================================================
// Helpers
// ===========================================================================

inline int u256_cmp(uint256 a, uint256 b) {
    for (int i = 3; i >= 0; --i) {
        if (a.limbs[i] < b.limbs[i]) return -1;
        if (a.limbs[i] > b.limbs[i]) return 1;
    }
    return 0;
}

inline bool u256_is_zero(uint256 a) {
    return (a.limbs[0] | a.limbs[1] | a.limbs[2] | a.limbs[3]) == 0;
}

inline void mul64(ulong a, ulong b, thread ulong &lo, thread ulong &hi) {
    ulong al = a & 0xFFFFFFFFUL;
    ulong ah = a >> 32;
    ulong bl = b & 0xFFFFFFFFUL;
    ulong bh = b >> 32;

    ulong ll = al * bl;
    ulong lh = al * bh;
    ulong hl = ah * bl;
    ulong hh = ah * bh;

    ulong mid = (ll >> 32) + (lh & 0xFFFFFFFFUL) + (hl & 0xFFFFFFFFUL);
    lo = (ll & 0xFFFFFFFFUL) | (mid << 32);
    hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}

inline ulong addc(ulong a, ulong b, ulong c, thread ulong &out) {
    ulong t = a + b;
    ulong c1 = (t < a) ? 1UL : 0UL;
    ulong t2 = t + c;
    ulong c2 = (t2 < t) ? 1UL : 0UL;
    out = t2;
    return c1 + c2;
}

inline ulong subb(ulong a, ulong b, ulong br, thread ulong &out) {
    ulong t = a - b;
    ulong b1 = (t > a) ? 1UL : 0UL;
    ulong t2 = t - br;
    ulong b2 = (t2 > t) ? 1UL : 0UL;
    out = t2;
    return b1 + b2;
}

inline uint256 add_256(uint256 a, uint256 b, thread ulong &carry) {
    uint256 r;
    ulong c = 0;
    for (int i = 0; i < 4; ++i) c = addc(a.limbs[i], b.limbs[i], c, r.limbs[i]);
    carry = c;
    return r;
}

inline uint256 sub_256(uint256 a, uint256 b, thread ulong &borrow) {
    uint256 r;
    ulong br = 0;
    for (int i = 0; i < 4; ++i) br = subb(a.limbs[i], b.limbs[i], br, r.limbs[i]);
    borrow = br;
    return r;
}

inline uint256 mod_add(uint256 a, uint256 b, uint256 m) {
    ulong c;
    uint256 t = add_256(a, b, c);
    if (c != 0 || u256_cmp(t, m) >= 0) {
        ulong bw;
        t = sub_256(t, m, bw);
    }
    return t;
}

inline uint256 mod_sub(uint256 a, uint256 b, uint256 m) {
    ulong bw;
    uint256 t = sub_256(a, b, bw);
    if (bw != 0) {
        ulong c;
        t = add_256(t, m, c);
    }
    return t;
}

inline uint256 mont_mul(uint256 a, uint256 b, uint256 m, ulong m_inv) {
    ulong t[6];
    for (int i = 0; i < 6; ++i) t[i] = 0;

    for (int i = 0; i < 4; ++i) {
        ulong carry = 0;
        for (int j = 0; j < 4; ++j) {
            ulong lo, hi;
            mul64(a.limbs[j], b.limbs[i], lo, hi);
            ulong c1 = addc(t[j], lo, carry, t[j]);
            carry = hi + c1;
        }
        ulong c1 = addc(t[4], carry, 0, t[4]);
        t[5] += c1;

        ulong u = t[0] * m_inv;

        carry = 0;
        for (int j = 0; j < 4; ++j) {
            ulong lo, hi;
            mul64(u, m.limbs[j], lo, hi);
            ulong c2 = addc(t[j], lo, carry, t[j]);
            carry = hi + c2;
        }
        ulong c2 = addc(t[4], carry, 0, t[4]);
        t[5] += c2;

        for (int j = 0; j < 5; ++j) t[j] = t[j + 1];
        t[5] = 0;
    }

    uint256 r = {{ t[0], t[1], t[2], t[3] }};
    if (t[4] != 0 || u256_cmp(r, m) >= 0) {
        ulong bw;
        r = sub_256(r, m, bw);
    }
    return r;
}

inline uint256 to_mont(uint256 a, uint256 r2, uint256 m, ulong m_inv) {
    return mont_mul(a, r2, m, m_inv);
}
inline uint256 from_mont(uint256 a, uint256 m, ulong m_inv) {
    return mont_mul(a, ONE, m, m_inv);
}

inline uint256 fp_add(uint256 a, uint256 b) { return mod_add(a, b, P_MOD); }
inline uint256 fp_sub(uint256 a, uint256 b) { return mod_sub(a, b, P_MOD); }
inline uint256 fp_mul(uint256 a, uint256 b) { return mont_mul(a, b, P_MOD, P_INV); }
inline uint256 fp_sqr(uint256 a) { return mont_mul(a, a, P_MOD, P_INV); }

inline uint256 fp_pow(uint256 a_mont, constant ulong* exp4) {
    uint256 result = ONE_MONT_P;
    uint256 base = a_mont;
    for (int limb = 0; limb < 4; ++limb) {
        ulong w = exp4[limb];
        for (int bit = 0; bit < 64; ++bit) {
            if ((w >> bit) & 1) result = fp_mul(result, base);
            base = fp_sqr(base);
        }
    }
    return result;
}

inline uint256 fp_inv(uint256 a_mont) { return fp_pow(a_mont, P_M2); }

inline bool fp_sqrt(uint256 a_mont, thread uint256 &out) {
    uint256 cand = fp_pow(a_mont, PP1_4);
    if (u256_cmp(fp_sqr(cand), a_mont) != 0) return false;
    out = cand;
    return true;
}

inline uint256 fn_mul(uint256 a, uint256 b) { return mont_mul(a, b, N_MOD, N_INV); }
inline uint256 fn_sqr(uint256 a) { return mont_mul(a, a, N_MOD, N_INV); }

inline uint256 fn_pow(uint256 a_mont, constant ulong* exp4) {
    uint256 result = mont_mul(ONE, R2_N, N_MOD, N_INV);
    uint256 base = a_mont;
    for (int limb = 0; limb < 4; ++limb) {
        ulong w = exp4[limb];
        for (int bit = 0; bit < 64; ++bit) {
            if ((w >> bit) & 1) result = fn_mul(result, base);
            base = fn_sqr(base);
        }
    }
    return result;
}

inline uint256 fn_inv(uint256 a_mont) { return fn_pow(a_mont, N_M2); }

// ===========================================================================
// EC point operations
// ===========================================================================

struct AffinePt { uint256 x; uint256 y; bool inf; };
struct JacPt    { uint256 X; uint256 Y; uint256 Z; bool inf; };

inline JacPt jac_zero() {
    JacPt r; r.X = ZERO; r.Y = ZERO; r.Z = ZERO; r.inf = true; return r;
}

inline JacPt aff_to_jac(AffinePt p) {
    if (p.inf) return jac_zero();
    JacPt r; r.X = p.x; r.Y = p.y; r.Z = ONE_MONT_P; r.inf = false;
    return r;
}

inline AffinePt jac_to_aff(JacPt p) {
    AffinePt a;
    if (p.inf || u256_is_zero(p.Z)) { a.x = ZERO; a.y = ZERO; a.inf = true; return a; }
    uint256 zi = fp_inv(p.Z);
    uint256 zi2 = fp_sqr(zi);
    uint256 zi3 = fp_mul(zi2, zi);
    a.x = fp_mul(p.X, zi2);
    a.y = fp_mul(p.Y, zi3);
    a.inf = false;
    return a;
}

inline JacPt jac_double(JacPt p) {
    if (p.inf) return p;
    if (u256_is_zero(p.Y)) return jac_zero();
    uint256 A = fp_sqr(p.X);
    uint256 B = fp_sqr(p.Y);
    uint256 C = fp_sqr(B);
    uint256 XplusB = fp_add(p.X, B);
    uint256 D = fp_sub(fp_sqr(XplusB), A);
    D = fp_sub(D, C);
    D = fp_add(D, D);
    uint256 E = fp_add(A, A); E = fp_add(E, A);
    uint256 F = fp_sqr(E);
    uint256 X3 = fp_sub(F, fp_add(D, D));
    uint256 D_m_X3 = fp_sub(D, X3);
    uint256 eight_C = fp_add(C, C); eight_C = fp_add(eight_C, eight_C); eight_C = fp_add(eight_C, eight_C);
    uint256 Y3 = fp_sub(fp_mul(E, D_m_X3), eight_C);
    uint256 Z3 = fp_mul(p.Y, p.Z); Z3 = fp_add(Z3, Z3);
    JacPt r; r.X = X3; r.Y = Y3; r.Z = Z3; r.inf = false; return r;
}

inline JacPt jac_add(JacPt p, JacPt q) {
    if (p.inf) return q;
    if (q.inf) return p;
    uint256 Z1Z1 = fp_sqr(p.Z);
    uint256 Z2Z2 = fp_sqr(q.Z);
    uint256 U1 = fp_mul(p.X, Z2Z2);
    uint256 U2 = fp_mul(q.X, Z1Z1);
    uint256 S1 = fp_mul(p.Y, fp_mul(Z2Z2, q.Z));
    uint256 S2 = fp_mul(q.Y, fp_mul(Z1Z1, p.Z));
    uint256 H = fp_sub(U2, U1);
    uint256 r = fp_sub(S2, S1);
    if (u256_is_zero(H)) {
        if (u256_is_zero(r)) return jac_double(p);
        return jac_zero();
    }
    uint256 HH = fp_sqr(H);
    uint256 HHH = fp_mul(H, HH);
    uint256 U1HH = fp_mul(U1, HH);
    uint256 X3 = fp_sub(fp_sqr(r), HHH);
    X3 = fp_sub(X3, fp_add(U1HH, U1HH));
    uint256 Y3 = fp_mul(r, fp_sub(U1HH, X3));
    Y3 = fp_sub(Y3, fp_mul(S1, HHH));
    uint256 Z3 = fp_mul(fp_mul(p.Z, q.Z), H);
    JacPt out; out.X = X3; out.Y = Y3; out.Z = Z3; out.inf = false; return out;
}

inline JacPt jac_mul(uint256 k, AffinePt p) {
    if (p.inf) return jac_zero();
    JacPt r = jac_zero();
    JacPt base = aff_to_jac(p);
    for (int limb = 3; limb >= 0; --limb) {
        ulong w = k.limbs[limb];
        for (int bit = 63; bit >= 0; --bit) {
            r = jac_double(r);
            if ((w >> bit) & 1) r = jac_add(r, base);
        }
    }
    return r;
}

// ===========================================================================
// Keccak-256 (Ethereum, delimiter 0x01)
// ===========================================================================

constant ulong RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL,
    0x800000000000808AUL, 0x8000000080008000UL,
    0x000000000000808BUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008AUL, 0x0000000000000088UL,
    0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL,
    0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800AUL, 0x800000008000000AUL,
    0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL,
};

// Same offsets as src/keccak/keccak.cpp (mod 64).
constant int R_OFFSETS[5][5] = {
    {  0, 36,  3, 41, 18},
    {  1, 44, 10, 45,  2},
    { 62,  6, 43, 15, 61},
    { 28, 55, 25, 21, 56},
    { 27, 20, 39,  8, 14},
};

inline ulong rotl64(ulong x, int n) {
    n &= 63;
    if (n == 0) return x;
    return (x << n) | (x >> (64 - n));
}

inline void keccakf1600(thread ulong* a) {
    ulong C[5], D[5], B[25];
    for (int round = 0; round < 24; ++round) {
        for (int x = 0; x < 5; ++x)
            C[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (int x = 0; x < 5; ++x)
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        for (int y = 0; y < 5; ++y)
            for (int x = 0; x < 5; ++x)
                a[x + 5 * y] ^= D[x];

        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y) {
                int nx = y;
                int ny = (2 * x + 3 * y) % 5;
                B[nx + 5 * ny] = rotl64(a[x + 5 * y], R_OFFSETS[x][y]);
            }

        for (int y = 0; y < 5; ++y) {
            ulong row[5];
            for (int x = 0; x < 5; ++x) row[x] = B[x + 5 * y];
            for (int x = 0; x < 5; ++x)
                a[x + 5 * y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5]);
        }

        a[0] ^= RC[round];
    }
}

inline void keccak256_64(thread const uchar* in, thread uchar* out) {
    const int RATE = 136;
    (void)RATE;
    ulong state[25];
    for (int i = 0; i < 25; ++i) state[i] = 0;

    uchar block[136];
    for (int i = 0; i < 64; ++i) block[i] = in[i];
    for (int i = 64; i < 136; ++i) block[i] = 0;
    block[64] = 0x01;
    block[135] |= 0x80;

    for (int j = 0; j < 17; ++j) {
        ulong v = 0;
        for (int b = 0; b < 8; ++b) v |= ((ulong)block[j * 8 + b]) << (8 * b);
        state[j] ^= v;
    }
    keccakf1600(state);

    for (int j = 0; j < 4; ++j) {
        ulong v = state[j];
        for (int b = 0; b < 8; ++b) {
            out[j * 8 + b] = (uchar)(v & 0xFF);
            v >>= 8;
        }
    }
}

// ===========================================================================
// I/O structs
// ===========================================================================

struct EcrecoverInput {
    uchar hash[32];
    uchar r[32];
    uchar s[32];
    uchar v;
    uchar _pad[15];
};

struct EcrecoverOutput {
    uchar address[20];
    uchar valid;
    uchar _pad[11];
};

inline uint256 load_be32(thread const uchar* b) {
    uint256 r;
    for (int limb = 0; limb < 4; ++limb) {
        ulong v = 0;
        int base = (3 - limb) * 8;
        for (int i = 0; i < 8; ++i) v = (v << 8) | (ulong)b[base + i];
        r.limbs[limb] = v;
    }
    return r;
}

inline void store_be32(uint256 a, thread uchar* b) {
    for (int limb = 0; limb < 4; ++limb) {
        int base = (3 - limb) * 8;
        ulong v = a.limbs[limb];
        for (int i = 7; i >= 0; --i) {
            b[base + i] = (uchar)(v & 0xFF);
            v >>= 8;
        }
    }
}

// ===========================================================================
// Main kernel
// ===========================================================================

kernel void secp256k1_ecrecover_batch(
    device const EcrecoverInput* inputs    [[buffer(0)]],
    device       EcrecoverOutput* outputs  [[buffer(1)]],
    constant uint& num                     [[buffer(2)]],
    uint tid                               [[thread_position_in_grid]])
{
    if (tid >= num) return;
    device const EcrecoverInput& in = inputs[tid];
    device       EcrecoverOutput& out = outputs[tid];

    for (int i = 0; i < 20; ++i) out.address[i] = 0;
    out.valid = 0;
    for (int i = 0; i < 11; ++i) out._pad[i] = 0;

    uchar hash_buf[32], r_buf[32], s_buf[32];
    for (int i = 0; i < 32; ++i) hash_buf[i] = in.hash[i];
    for (int i = 0; i < 32; ++i) r_buf[i]    = in.r[i];
    for (int i = 0; i < 32; ++i) s_buf[i]    = in.s[i];
    uchar v = in.v;
    if (v >= 27) v -= 27;
    if (v >  1)  v %= 2;

    uint256 r = load_be32(r_buf);
    uint256 s = load_be32(s_buf);
    uint256 e = load_be32(hash_buf);

    if (u256_is_zero(r) || u256_cmp(r, N_MOD) >= 0) return;
    if (u256_is_zero(s) || u256_cmp(s, N_MOD) >= 0) return;
    if (v > 1) return;

    uint256 r_pm  = to_mont(r, R2_P, P_MOD, P_INV);
    uint256 r2m   = fp_sqr(r_pm);
    uint256 r3m   = fp_mul(r2m, r_pm);
    uint256 sevn  = {{7, 0, 0, 0}};
    uint256 sevnm = to_mont(sevn, R2_P, P_MOD, P_INV);
    uint256 y2m   = fp_add(r3m, sevnm);

    uint256 ym;
    if (!fp_sqrt(y2m, ym)) return;
    uint256 yn = from_mont(ym, P_MOD, P_INV);
    bool y_odd = (yn.limbs[0] & 1UL) != 0;
    bool want_odd = (v == 1);
    if (y_odd != want_odd) ym = fp_sub(ZERO, ym);

    AffinePt R_pt; R_pt.x = r_pm; R_pt.y = ym; R_pt.inf = false;

    uint256 e_red = e;
    if (u256_cmp(e_red, N_MOD) >= 0) {
        ulong bw; e_red = sub_256(e_red, N_MOD, bw);
    }
    uint256 r_nm    = to_mont(r,     R2_N, N_MOD, N_INV);
    uint256 r_inv   = fn_inv(r_nm);
    uint256 e_nm    = to_mont(e_red, R2_N, N_MOD, N_INV);
    uint256 s_nm    = to_mont(s,     R2_N, N_MOD, N_INV);
    uint256 u1_nm   = fn_mul(e_nm, r_inv);
    uint256 u1_norm = from_mont(u1_nm, N_MOD, N_INV);
    if (!u256_is_zero(u1_norm)) {
        ulong bw; u1_norm = sub_256(N_MOD, u1_norm, bw);
    }
    uint256 u2_norm = from_mont(fn_mul(s_nm, r_inv), N_MOD, N_INV);

    AffinePt G;
    G.x = to_mont(GX_PLAIN, R2_P, P_MOD, P_INV);
    G.y = to_mont(GY_PLAIN, R2_P, P_MOD, P_INV);
    G.inf = false;

    JacPt Q1 = jac_mul(u1_norm, G);
    JacPt Q2 = jac_mul(u2_norm, R_pt);
    JacPt Q  = jac_add(Q1, Q2);
    AffinePt Qa = jac_to_aff(Q);
    if (Qa.inf) return;

    uint256 qx = from_mont(Qa.x, P_MOD, P_INV);
    uint256 qy = from_mont(Qa.y, P_MOD, P_INV);

    uchar pubkey[64];
    store_be32(qx, pubkey);
    store_be32(qy, pubkey + 32);

    uchar hash_addr[32];
    keccak256_64(pubkey, hash_addr);

    for (int i = 0; i < 20; ++i) out.address[i] = hash_addr[12 + i];
    out.valid = 1;
}

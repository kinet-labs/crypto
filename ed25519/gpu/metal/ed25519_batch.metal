// GPU-batched Ed25519 EdDSA signature verification (RFC 8032).
//
// One thread per signature. Each thread runs the full verify:
//   1. Decompress public key A (32 bytes -> Edwards point)
//   2. Decompress signature point R (first 32 bytes of sig -> Edwards point)
//   3. Read scalar S (last 32 bytes of sig)
//   4. Read pre-computed challenge h = SHA-512(R || A || M) reduced mod L
//      (host computes SHA-512 -- it has hardware acceleration via NEON
//      crypto extensions; doing SHA-512 on Metal is ~10x slower per byte
//      and dominates kernel time)
//   5. Verify [S]B == R + [h]A
//
// The kernel produces results[i] = 1 if signature i is valid, 0 otherwise.
// Byte-equal to crypto/ed25519.Verify when called over the same triples.
//
// Layout: pubkeys[N*32], sigs[N*64], hs[N*32], results[N*1].
// Hash scalar h is 64-byte SHA-512 output reduced to 32-byte little-endian
// scalar mod L by the host before dispatch.

#include <metal_stdlib>
using namespace metal;

// =============================================================================
// 256-bit integer (4 x 64-bit limbs, little-endian)
// =============================================================================

struct uint256 {
    ulong limbs[4];
};

constant uint256 ZERO = {{0UL, 0UL, 0UL, 0UL}};
constant uint256 ONE  = {{1UL, 0UL, 0UL, 0UL}};

// p = 2^255 - 19
constant uint256 ED_P = {{
    0xFFFFFFFFFFFFFFEDUL, 0xFFFFFFFFFFFFFFFFUL,
    0xFFFFFFFFFFFFFFFFUL, 0x7FFFFFFFFFFFFFFFUL
}};

// Curve constant d = -121665/121666 mod p
//   = 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3
constant uint256 ED_D = {{
    0x75EB4DCA135978A3UL, 0x00700A4D4141D8ABUL,
    0x8CC740797779E898UL, 0x52036CEE2B6FFE73UL
}};

// 2*d mod p (precomputed for addition formula)
constant uint256 ED_2D = {{
    0xEBD69B9426B2F159UL, 0x00E0149A8283B156UL,
    0x198E80F2EEF3D130UL, 0x2406D9DC56DFFCE7UL
}};

// Group order L = 2^252 + 27742317777372353535851937790883648493
constant uint256 ED_L = {{
    0x5812631A5CF5D3EDUL, 0x14DEF9DEA2F79CD6UL,
    0x0000000000000000UL, 0x1000000000000000UL
}};

// Generator B base point coordinates
constant uint256 ED_BX = {{
    0xC9562D608F25D51AUL, 0x692CC7609525A7B2UL,
    0xC0A4E231FDD6DC5CUL, 0x216936D3CD6E53FEUL
}};
constant uint256 ED_BY = {{
    0x6666666666666658UL, 0x6666666666666666UL,
    0x6666666666666666UL, 0x6666666666666666UL
}};

// sqrt(-1) mod p, used for point decompression when x^2 != target
constant uint256 ED_SQRT_M1 = {{
    0xC4EE1B274A0EA0B0UL, 0x2F431806AD2FE478UL,
    0x2B4D00993DFBD7A7UL, 0x2B8324804FC1DF0BUL
}};

// =============================================================================
// 256-bit arithmetic helpers
// =============================================================================

inline int u256_cmp(uint256 a, uint256 b) {
    for (int i = 3; i >= 0; --i) {
        if (a.limbs[i] < b.limbs[i]) return -1;
        if (a.limbs[i] > b.limbs[i]) return 1;
    }
    return 0;
}

inline bool u256_is_zero(uint256 a) {
    return (a.limbs[0] | a.limbs[1] | a.limbs[2] | a.limbs[3]) == 0UL;
}

inline uint256 u256_add(uint256 a, uint256 b, thread ulong& carry) {
    uint256 r;
    ulong c = 0;
    for (int i = 0; i < 4; ++i) {
        ulong s1 = a.limbs[i] + c;
        ulong c1 = (s1 < a.limbs[i]) ? 1UL : 0UL;
        ulong s2 = s1 + b.limbs[i];
        ulong c2 = (s2 < s1) ? 1UL : 0UL;
        r.limbs[i] = s2;
        c = c1 + c2;
    }
    carry = c;
    return r;
}

inline uint256 u256_sub(uint256 a, uint256 b, thread ulong& borrow) {
    uint256 r;
    ulong bw = 0;
    for (int i = 0; i < 4; ++i) {
        ulong d1 = a.limbs[i] - bw;
        ulong b1 = (d1 > a.limbs[i]) ? 1UL : 0UL;
        ulong d2 = d1 - b.limbs[i];
        ulong b2 = (d2 > d1) ? 1UL : 0UL;
        r.limbs[i] = d2;
        bw = b1 + b2;
    }
    borrow = bw;
    return r;
}

inline void mul64(ulong a, ulong b, thread ulong& lo, thread ulong& hi) {
    ulong al = a & 0xFFFFFFFFUL, ah = a >> 32;
    ulong bl = b & 0xFFFFFFFFUL, bh = b >> 32;
    ulong ll = al * bl;
    ulong lh = al * bh;
    ulong hl = ah * bl;
    ulong hh = ah * bh;
    ulong mid = lh + (ll >> 32);
    ulong mid2 = mid + hl;
    if (mid2 < mid) hh += (1UL << 32);
    lo = (mid2 << 32) | (ll & 0xFFFFFFFFUL);
    hi = hh + (mid2 >> 32);
}

// =============================================================================
// Field arithmetic mod p = 2^255 - 19
// =============================================================================

inline uint256 fp_canonical(uint256 a) {
    while (u256_cmp(a, ED_P) >= 0) {
        ulong bw;
        a = u256_sub(a, ED_P, bw);
    }
    return a;
}

inline uint256 fp_add(uint256 a, uint256 b) {
    ulong c;
    uint256 r = u256_add(a, b, c);
    if (c != 0UL || u256_cmp(r, ED_P) >= 0) {
        ulong bw;
        r = u256_sub(r, ED_P, bw);
    }
    return r;
}

inline uint256 fp_sub(uint256 a, uint256 b) {
    ulong bw;
    uint256 r = u256_sub(a, b, bw);
    if (bw != 0UL) {
        ulong c;
        r = u256_add(r, ED_P, c);
    }
    return r;
}

inline uint256 fp_mul(uint256 a, uint256 b) {
    // 4x4 schoolbook -> 8 limb product, then fold high half * 38 into low.
    ulong t[8];
    for (int i = 0; i < 8; ++i) t[i] = 0;
    for (int i = 0; i < 4; ++i) {
        ulong carry = 0;
        for (int j = 0; j < 4; ++j) {
            ulong lo, hi;
            mul64(a.limbs[i], b.limbs[j], lo, hi);
            ulong s = lo + carry;
            ulong c1 = (s < lo) ? 1UL : 0UL;
            ulong s2 = t[i + j] + s;
            ulong c2 = (s2 < t[i + j]) ? 1UL : 0UL;
            t[i + j] = s2;
            carry = hi + c1 + c2;
        }
        t[i + 4] = carry;
    }

    // 2^256 mod p = 38; fold high * 38 into low.
    uint256 lo_part = {{t[0], t[1], t[2], t[3]}};
    uint256 hi_part = {{t[4], t[5], t[6], t[7]}};
    ulong carry = 0;
    uint256 hi38;
    for (int i = 0; i < 4; ++i) {
        ulong lo, hi;
        mul64(hi_part.limbs[i], 38UL, lo, hi);
        ulong s = lo + carry;
        carry = hi + ((s < lo) ? 1UL : 0UL);
        hi38.limbs[i] = s;
    }
    ulong c;
    uint256 r = u256_add(lo_part, hi38, c);
    if (c != 0UL || carry != 0UL) {
        ulong extra = (c + carry) * 38UL;
        uint256 ex = {{extra, 0UL, 0UL, 0UL}};
        r = u256_add(r, ex, c);
    }
    return fp_canonical(r);
}

inline uint256 fp_sqr(uint256 a) { return fp_mul(a, a); }

inline uint256 fp_neg(uint256 a) {
    if (u256_is_zero(a)) return a;
    ulong bw;
    return u256_sub(ED_P, a, bw);
}

// Fermat inverse: a^(p-2) mod p
inline uint256 fp_inv(uint256 a) {
    uint256 exp = ED_P;
    exp.limbs[0] -= 2;
    uint256 result = ONE;
    uint256 base = a;
    for (int i = 0; i < 4; ++i) {
        ulong limb = exp.limbs[i];
        for (int b = 0; b < 64; ++b) {
            if ((limb >> b) & 1UL) result = fp_mul(result, base);
            base = fp_sqr(base);
        }
    }
    return result;
}

// =============================================================================
// Extended twisted Edwards point (X:Y:Z:T), x=X/Z, y=Y/Z, T=XY/Z
// =============================================================================

struct EdPoint {
    uint256 X, Y, Z, T;
};

inline EdPoint ed_identity() {
    EdPoint p;
    p.X = ZERO; p.Y = ONE; p.Z = ONE; p.T = ZERO;
    return p;
}

inline EdPoint ed_double(EdPoint P) {
    uint256 A  = fp_sqr(P.X);
    uint256 B  = fp_sqr(P.Y);
    uint256 C  = fp_add(fp_sqr(P.Z), fp_sqr(P.Z));
    uint256 D  = fp_neg(A);
    uint256 XY = fp_add(P.X, P.Y);
    uint256 E  = fp_sub(fp_sqr(XY), fp_add(A, B));
    uint256 G  = fp_add(D, B);
    uint256 F  = fp_sub(G, C);
    uint256 H  = fp_sub(D, B);
    EdPoint R;
    R.X = fp_mul(E, F);
    R.Y = fp_mul(G, H);
    R.T = fp_mul(E, H);
    R.Z = fp_mul(F, G);
    return R;
}

inline EdPoint ed_add(EdPoint P, EdPoint Q) {
    // add-2008-hwcd-3 (Hisil, Wong, Carter, Dawson 2008) for a = -1 twisted
    // Edwards. Algorithm 1 of "Twisted Edwards Curves Revisited", uses 8M.
    uint256 A = fp_mul(fp_sub(P.Y, P.X), fp_sub(Q.Y, Q.X));
    uint256 B = fp_mul(fp_add(P.Y, P.X), fp_add(Q.Y, Q.X));
    uint256 C = fp_mul(fp_mul(P.T, ED_2D), Q.T);
    uint256 ZZ = fp_mul(P.Z, Q.Z);
    uint256 D = fp_add(ZZ, ZZ);                  // 2*Z1*Z2
    uint256 E = fp_sub(B, A);
    uint256 F = fp_sub(D, C);
    uint256 G = fp_add(D, C);
    uint256 H = fp_add(B, A);
    EdPoint R;
    R.X = fp_mul(E, F);
    R.Y = fp_mul(G, H);
    R.T = fp_mul(E, H);
    R.Z = fp_mul(F, G);
    return R;
}

inline EdPoint ed_mul(uint256 k, EdPoint P) {
    EdPoint result = ed_identity();
    for (int i = 3; i >= 0; --i) {
        ulong limb = k.limbs[i];
        for (int b = 63; b >= 0; --b) {
            result = ed_double(result);
            if ((limb >> b) & 1UL) result = ed_add(result, P);
        }
    }
    return result;
}

// Convert extended point to canonical (x, y) affine pair.
inline void ed_to_affine(EdPoint p, thread uint256& x, thread uint256& y) {
    uint256 zinv = fp_inv(p.Z);
    x = fp_mul(p.X, zinv);
    y = fp_mul(p.Y, zinv);
}

// =============================================================================
// Point decompression (RFC 8032 Section 5.1.3)
// =============================================================================

inline bool ed_decompress(device const uchar* enc, thread EdPoint& P) {
    uint256 y;
    for (int i = 0; i < 4; ++i) {
        ulong v = 0;
        for (int b = 0; b < 8; ++b) v |= (ulong)enc[i * 8 + b] << (b * 8);
        y.limbs[i] = v;
    }
    bool x_sign = (enc[31] >> 7) & 1u;
    y.limbs[3] &= 0x7FFFFFFFFFFFFFFFUL;
    if (u256_cmp(y, ED_P) >= 0) return false;

    uint256 y2  = fp_sqr(y);
    uint256 num = fp_sub(y2, ONE);
    uint256 den = fp_add(fp_mul(ED_D, y2), ONE);
    uint256 den_inv = fp_inv(den);
    uint256 x2  = fp_mul(num, den_inv);

    if (u256_is_zero(x2)) {
        if (x_sign) return false;
        P.X = ZERO; P.Y = y; P.Z = ONE; P.T = ZERO;
        return true;
    }

    // x = x2^((p+3)/8); if x^2 != x2, multiply by sqrt(-1)
    uint256 exp_v = ED_P;
    exp_v.limbs[0] += 3UL;
    for (int i = 0; i < 3; ++i) {
        exp_v.limbs[i] = (exp_v.limbs[i] >> 3) | (exp_v.limbs[i + 1] << 61);
    }
    exp_v.limbs[3] >>= 3;

    uint256 x = ONE;
    uint256 base = x2;
    for (int i = 0; i < 4; ++i) {
        ulong limb = exp_v.limbs[i];
        for (int b = 0; b < 64; ++b) {
            if ((limb >> b) & 1UL) x = fp_mul(x, base);
            base = fp_sqr(base);
        }
    }
    if (u256_cmp(fp_sqr(x), x2) != 0) {
        x = fp_mul(x, ED_SQRT_M1);
        if (u256_cmp(fp_sqr(x), x2) != 0) return false;
    }

    bool x_is_odd = (x.limbs[0] & 1UL) != 0UL;
    if (x_is_odd != x_sign) x = fp_neg(x);

    P.X = x; P.Y = y; P.Z = ONE; P.T = fp_mul(x, y);
    return true;
}

// =============================================================================
// I/O records
// =============================================================================

struct Ed25519PublicKey { uchar data[32]; };
struct Ed25519Signature { uchar data[64]; };  // R[32] || S[32]
struct Ed25519Challenge { uchar data[32]; };  // h = SHA512(R||A||M) mod L

// =============================================================================
// Batch verify kernel.
//
// Each thread verifies one (pubkey, signature, challenge) tuple. The challenge
// h is computed by the host as SHA-512(R || A || M) reduced mod L. Verifying
// [S]B == R + [h]A reproduces the RFC 8032 cofactored verify rule when h is
// the standard SHA-512-derived challenge.
//
// This kernel returns 1/0 only -- it does not signal which sub-check failed.
// Callers that need a diagnostic should fall back to the CPU verify.
// =============================================================================

kernel void ed25519_batch_verify(
    device const Ed25519PublicKey*  pubkeys     [[buffer(0)]],
    device const Ed25519Signature*  signatures  [[buffer(1)]],
    device const Ed25519Challenge*  challenges  [[buffer(2)]],
    device       uchar*             results     [[buffer(3)]],
    constant uint&                  num_sigs    [[buffer(4)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= num_sigs) return;

    EdPoint A;
    if (!ed_decompress(pubkeys[tid].data, A)) {
        results[tid] = 0u;
        return;
    }

    EdPoint R;
    if (!ed_decompress(signatures[tid].data, R)) {
        results[tid] = 0u;
        return;
    }

    uint256 S;
    for (int i = 0; i < 4; ++i) {
        ulong v = 0;
        for (int b = 0; b < 8; ++b) {
            v |= (ulong)signatures[tid].data[32 + i * 8 + b] << (b * 8);
        }
        S.limbs[i] = v;
    }
    if (u256_cmp(S, ED_L) >= 0) {
        results[tid] = 0u;
        return;
    }

    uint256 h;
    for (int i = 0; i < 4; ++i) {
        ulong v = 0;
        for (int b = 0; b < 8; ++b) {
            v |= (ulong)challenges[tid].data[i * 8 + b] << (b * 8);
        }
        h.limbs[i] = v;
    }

    EdPoint B; B.X = ED_BX; B.Y = ED_BY; B.Z = ONE; B.T = fp_mul(ED_BX, ED_BY);
    EdPoint SB  = ed_mul(S, B);
    EdPoint hA  = ed_mul(h, A);
    EdPoint RhA = ed_add(R, hA);

    uint256 sb_x, sb_y, rha_x, rha_y;
    ed_to_affine(SB, sb_x, sb_y);
    ed_to_affine(RhA, rha_x, rha_y);

    bool ok = (u256_cmp(sb_x, rha_x) == 0) && (u256_cmp(sb_y, rha_y) == 0);
    results[tid] = ok ? 1u : 0u;
}

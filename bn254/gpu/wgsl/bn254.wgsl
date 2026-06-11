// First-party WebGPU/WGSL kernels for bn254 (alt_bn128).
//
// Algorithm transliteration of bn254/cpp/{bn254_fp,bn254_g1,bn254_hash_to_curve}
// .hpp. WGSL has no native u64, so each CPU u64 limb is encoded as a pair of
// u32 (lo, hi) in LE order. Wire layout matches CPU bytes-for-bytes:
//   CPU u64 limb i  ==  WGSL { lo = u32[2i], hi = u32[2i+1] }
//
// 4 x u64 CPU == 8 x u32 WGSL.
//
// Algorithms:
//   * Fp:   CIOS Montgomery multiplication (HAC §14.36)
//   * Fp2:  Karatsuba over Fp[u]/(u^2+1)
//   * Fp6:  Algorithms 13/16/17 of eprint 2010/354
//   * Fp12: generic Karatsuba mul + Granger-Scott cyclotomic squaring
//   * G1:   Bernstein-Lange efl/jacobian-0/{dbl-2009-l, add-2007-bl}
//   * G1 mul: constant-time Montgomery ladder over 256 bits (no early exit)
//   * G2:   homogeneous projective doubleStep / mixedAddStep / lineCompute
//   * Optimal-ate Miller loop: 6x+2 NAF, sparse 034-mul folding, two-line square
//   * Final exp: easy part (p^6-1)(p^2+1), hard part Fuentes-Castaneda
//   * SVDW: RFC 9380 §6.6.1 map_to_curve_svdw
//
// I/O packing:
//   Affine point: 18 x u32 = 9 x u64 == (x[8] || y[8] || inf[2])
//   Field element: 8 x u32 = 4 x u64
//   Scalar:        8 x u32 = 4 x u64
//
// Each kernel uses a contiguous storage buffer, indexed by global thread id.

// =============================================================================
// Constants (8 x u32, LE pairs of (lo, hi))
// =============================================================================
//
// p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
// CPU 4 x u64: { 0x3C208C16D87CFD47, 0x97816A916871CA8D, 0xB85045B68181585D, 0x30644E72E131A029 }
// WGSL 8 x u32 (lo,hi):
//   { 0xD87CFD47, 0x3C208C16, 0x6871CA8D, 0x97816A91,
//     0x8181585D, 0xB85045B6, 0xE131A029, 0x30644E72 }

const BN_P: array<u32, 8> = array<u32, 8>(
    0xD87CFD47u, 0x3C208C16u, 0x6871CA8Du, 0x97816A91u,
    0x8181585Du, 0xB85045B6u, 0xE131A029u, 0x30644E72u
);

const BN_R: array<u32, 8> = array<u32, 8>(
    0xC58F0D9Du, 0xD35D438Du, 0xF5C70B3Du, 0x0A78EB28u,
    0x7879462Cu, 0x666EA36Fu, 0x9A07DF2Fu, 0x0E0A77C1u
);

const BN_R2: array<u32, 8> = array<u32, 8>(
    0x538AFA89u, 0xF32CFC5Bu, 0xD44501FBu, 0xB5E71911u,
    0x0A417FF6u, 0x47AB1EFFu, 0xCAB8351Fu, 0x06D89F71u
);

// p_inv low 64 bits = 0x87D20782E4866389; (lo, hi) = (0xE4866389, 0x87D20782)
const BN_PINV_LO: u32 = 0xE4866389u;
const BN_PINV_HI: u32 = 0x87D20782u;

// p - 2  (for Fermat inversion)
const BN_PM2: array<u32, 8> = array<u32, 8>(
    0xD87CFD45u, 0x3C208C16u, 0x6871CA8Du, 0x97816A91u,
    0x8181585Du, 0xB85045B6u, 0xE131A029u, 0x30644E72u
);

// (p+1)/4  (for square root, since p ≡ 3 mod 4)
const BN_PP1_4: array<u32, 8> = array<u32, 8>(
    0xB61F3F52u, 0x4F082305u, 0x5A1C72A3u, 0x65E05AA4u,
    0xA0605617u, 0x6E14116Du, 0xB84C680Au, 0x0C19139Cu
);

// SVDW constants (plain).
const BN_SVDW_Z: array<u32, 8> = array<u32, 8>(
    1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u
);
const BN_SVDW_C1: array<u32, 8> = array<u32, 8>(
    4u, 0u, 0u, 0u, 0u, 0u, 0u, 0u
);
// 0x183227397098D014DC2822DB40C0AC2E CBC0B548B438E5469E10460B6C3E7EA3
const BN_SVDW_C2: array<u32, 8> = array<u32, 8>(
    0x6C3E7EA3u, 0x9E10460Bu, 0xB438E546u, 0xCBC0B548u,
    0x40C0AC2Eu, 0xDC2822DBu, 0x7098D014u, 0x18322739u
);
// 0x00000000 00000001 6789AF3A 83522EB3 53C98FC6 B36D713D 5D8D1CC5 DFFFFFFA
const BN_SVDW_C3: array<u32, 8> = array<u32, 8>(
    0xDFFFFFFAu, 0x5D8D1CC5u, 0xB36D713Du, 0x53C98FC6u,
    0x83522EB3u, 0x6789AF3Au, 0x00000001u, 0x00000000u
);
// 0x10216F7BA065E00DE81AC1E7808072C9DD2B2385CD7B438469602EB24829A9BD
const BN_SVDW_C4: array<u32, 8> = array<u32, 8>(
    0x4829A9BDu, 0x69602EB2u, 0xCD7B4384u, 0xDD2B2385u,
    0x808072C9u, 0xE81AC1E7u, 0xA065E00Du, 0x10216F7Bu
);

// =============================================================================
// 256-bit big-int primitives (8 x u32, LE)
// =============================================================================

fn u256_is_zero(a: array<u32, 8>) -> bool {
    var acc: u32 = 0u;
    for (var i = 0u; i < 8u; i = i + 1u) { acc = acc | a[i]; }
    return acc == 0u;
}

fn u256_eq(a: array<u32, 8>, b: array<u32, 8>) -> bool {
    var acc: u32 = 0u;
    for (var i = 0u; i < 8u; i = i + 1u) { acc = acc | (a[i] ^ b[i]); }
    return acc == 0u;
}

fn u256_cmp(a: array<u32, 8>, b: array<u32, 8>) -> i32 {
    for (var i = 7i; i >= 0; i = i - 1) {
        let ui = u32(i);
        if (a[ui] > b[ui]) { return 1; }
        if (a[ui] < b[ui]) { return -1; }
    }
    return 0;
}

fn u256_add(a: array<u32, 8>, b: array<u32, 8>, r: ptr<function, array<u32, 8>>) -> u32 {
    var c: u32 = 0u;
    for (var i = 0u; i < 8u; i = i + 1u) {
        let s1 = a[i] + c;
        var c1: u32 = 0u; if (s1 < a[i]) { c1 = 1u; }
        let s2 = s1 + b[i];
        var c2: u32 = 0u; if (s2 < s1) { c2 = 1u; }
        (*r)[i] = s2;
        c = c1 + c2;
    }
    return c;
}

fn u256_sub(a: array<u32, 8>, b: array<u32, 8>, r: ptr<function, array<u32, 8>>) -> u32 {
    var bw: u32 = 0u;
    for (var i = 0u; i < 8u; i = i + 1u) {
        let d1 = a[i] - bw;
        var b1: u32 = 0u; if (d1 > a[i]) { b1 = 1u; }
        let d2 = d1 - b[i];
        var b2: u32 = 0u; if (d2 > d1) { b2 = 1u; }
        (*r)[i] = d2;
        bw = b1 + b2;
    }
    return bw;
}

// 32 x 32 -> 64 split into (lo, hi).
fn mul32_64(a: u32, b: u32) -> vec2<u32> {
    let al = a & 0xFFFFu;
    let ah = a >> 16u;
    let bl = b & 0xFFFFu;
    let bh = b >> 16u;
    let ll = al * bl;
    let lh = al * bh;
    let hl = ah * bl;
    let hh = ah * bh;
    let mid = (ll >> 16u) + (lh & 0xFFFFu) + (hl & 0xFFFFu);
    let lo = (mid << 16u) | (ll & 0xFFFFu);
    let hi = hh + (lh >> 16u) + (hl >> 16u) + (mid >> 16u);
    return vec2<u32>(lo, hi);
}

// =============================================================================
// Modular add/sub mod p
// =============================================================================

fn mod_add_p(a: array<u32, 8>, b: array<u32, 8>) -> array<u32, 8> {
    var r: array<u32, 8>;
    let c = u256_add(a, b, &r);
    if (c != 0u || u256_cmp(r, BN_P) >= 0) {
        var t: array<u32, 8>;
        let _ = u256_sub(r, BN_P, &t);
        r = t;
    }
    return r;
}

fn mod_sub_p(a: array<u32, 8>, b: array<u32, 8>) -> array<u32, 8> {
    var r: array<u32, 8>;
    let bw = u256_sub(a, b, &r);
    if (bw != 0u) {
        var t: array<u32, 8>;
        let _ = u256_add(r, BN_P, &t);
        r = t;
    }
    return r;
}

// =============================================================================
// CIOS Montgomery multiplication
// =============================================================================
//
// Equivalent to CPU's mont_mul, working in 32-bit chunks. We follow the same
// outer structure: process 8 limbs of `b` (one 32-bit lane at a time); after
// each addition compute u = t[0] * p_inv (low 32 bits), then add u*p, then
// shift. Final reduction subtracts p once if needed.

fn mont_mul_p(a: array<u32, 8>, b: array<u32, 8>) -> array<u32, 8> {
    var t: array<u32, 10>;
    for (var i = 0u; i < 10u; i = i + 1u) { t[i] = 0u; }

    for (var i = 0u; i < 8u; i = i + 1u) {
        // t += a * b[i]
        var carry: u32 = 0u;
        for (var j = 0u; j < 8u; j = j + 1u) {
            let prod = mul32_64(a[j], b[i]);
            let lo = prod.x;
            let hi = prod.y;

            let s1 = t[j] + lo;
            var c1: u32 = 0u; if (s1 < t[j]) { c1 = 1u; }
            let s2 = s1 + carry;
            var c2: u32 = 0u; if (s2 < s1) { c2 = 1u; }
            t[j] = s2;
            carry = hi + c1 + c2;
        }
        let s8 = t[8] + carry;
        var c8: u32 = 0u; if (s8 < t[8]) { c8 = 1u; }
        t[8] = s8;
        t[9] = t[9] + c8;

        // u = t[0] * p_inv (mod 2^32). 64-bit u_inv * t[0] needs only the low 32 bits
        // of (t[0] * p_inv_full). For 32-bit lanes that = (t[0] * p_inv_lo) & 0xFFFFFFFF.
        let u_low = t[0] * BN_PINV_LO;

        // t += u_low * p
        carry = 0u;
        for (var j = 0u; j < 8u; j = j + 1u) {
            let prod = mul32_64(u_low, BN_P[j]);
            let lo = prod.x;
            let hi = prod.y;

            let s1 = t[j] + lo;
            var c1: u32 = 0u; if (s1 < t[j]) { c1 = 1u; }
            let s2 = s1 + carry;
            var c2: u32 = 0u; if (s2 < s1) { c2 = 1u; }
            t[j] = s2;
            carry = hi + c1 + c2;
        }
        let s8b = t[8] + carry;
        var c8b: u32 = 0u; if (s8b < t[8]) { c8b = 1u; }
        t[8] = s8b;
        t[9] = t[9] + c8b;

        // shift right one 32-bit limb
        for (var j = 0u; j < 9u; j = j + 1u) { t[j] = t[j+1u]; }
        t[9] = 0u;
    }

    var r: array<u32, 8>;
    for (var i = 0u; i < 8u; i = i + 1u) { r[i] = t[i]; }
    if (t[8] != 0u || u256_cmp(r, BN_P) >= 0) {
        var s: array<u32, 8>;
        let _ = u256_sub(r, BN_P, &s);
        r = s;
    }
    return r;
}

fn to_mont_p(a: array<u32, 8>) -> array<u32, 8> {
    return mont_mul_p(a, BN_R2);
}

fn from_mont_p(a: array<u32, 8>) -> array<u32, 8> {
    let one = array<u32, 8>(1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u);
    return mont_mul_p(a, one);
}

// =============================================================================
// Fp ops (alias)
// =============================================================================

fn fp_add(a: array<u32, 8>, b: array<u32, 8>) -> array<u32, 8> { return mod_add_p(a, b); }
fn fp_sub(a: array<u32, 8>, b: array<u32, 8>) -> array<u32, 8> { return mod_sub_p(a, b); }
fn fp_mul(a: array<u32, 8>, b: array<u32, 8>) -> array<u32, 8> { return mont_mul_p(a, b); }
fn fp_sqr(a: array<u32, 8>) -> array<u32, 8> { return mont_mul_p(a, a); }

fn fp_neg(a: array<u32, 8>) -> array<u32, 8> {
    if (u256_is_zero(a)) { return a; }
    var r: array<u32, 8>;
    let _ = u256_sub(BN_P, a, &r);
    return r;
}

fn fp_pow(a: array<u32, 8>, e: array<u32, 8>) -> array<u32, 8> {
    var result = to_mont_p(array<u32, 8>(1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u));
    var base = a;
    for (var limb = 0u; limb < 8u; limb = limb + 1u) {
        let w = e[limb];
        for (var bit = 0u; bit < 32u; bit = bit + 1u) {
            if ((w >> bit) & 1u) == 1u {
                result = fp_mul(result, base);
            }
            base = fp_sqr(base);
        }
    }
    return result;
}

fn fp_inv(a: array<u32, 8>) -> array<u32, 8> { return fp_pow(a, BN_PM2); }

struct SqrtRes { ok: bool, v: array<u32, 8> }

fn fp_sqrt(a: array<u32, 8>) -> SqrtRes {
    let cand = fp_pow(a, BN_PP1_4);
    var out: SqrtRes;
    if (u256_eq(fp_sqr(cand), a)) {
        out.ok = true;
        out.v = cand;
    } else {
        out.ok = false;
        out.v = a;
    }
    return out;
}

fn fp_three() -> array<u32, 8> {
    return to_mont_p(array<u32, 8>(3u, 0u, 0u, 0u, 0u, 0u, 0u, 0u));
}

// =============================================================================
// G1 Jacobian
// =============================================================================

struct G1A { x: array<u32, 8>, y: array<u32, 8>, inf: u32 }
struct G1J { X: array<u32, 8>, Y: array<u32, 8>, Z: array<u32, 8>, inf: u32 }

fn g1_jac_zero() -> G1J {
    var r: G1J;
    for (var i = 0u; i < 8u; i = i + 1u) { r.X[i] = 0u; r.Y[i] = 0u; r.Z[i] = 0u; }
    r.inf = 1u;
    return r;
}

fn g1_to_jac(p: G1A) -> G1J {
    if (p.inf != 0u) { return g1_jac_zero(); }
    var r: G1J;
    r.X = p.x; r.Y = p.y; r.Z = BN_R; r.inf = 0u;
    return r;
}

fn g1_to_affine(p: G1J) -> G1A {
    var a: G1A;
    if (p.inf != 0u || u256_is_zero(p.Z)) {
        for (var i = 0u; i < 8u; i = i + 1u) { a.x[i] = 0u; a.y[i] = 0u; }
        a.inf = 1u;
        return a;
    }
    let z_inv  = fp_inv(p.Z);
    let z_inv2 = fp_sqr(z_inv);
    let z_inv3 = fp_mul(z_inv2, z_inv);
    a.x = fp_mul(p.X, z_inv2);
    a.y = fp_mul(p.Y, z_inv3);
    a.inf = 0u;
    return a;
}

fn g1_double(p: G1J) -> G1J {
    if (p.inf != 0u) { return p; }
    if (u256_is_zero(p.Y)) { return g1_jac_zero(); }

    let A = fp_sqr(p.X);
    let B = fp_sqr(p.Y);
    let C = fp_sqr(B);

    let X_plus_B = fp_add(p.X, B);
    var D = fp_sub(fp_sqr(X_plus_B), A);
    D = fp_sub(D, C);
    D = fp_add(D, D);

    var E = fp_add(A, A);
    E = fp_add(E, A);
    let F = fp_sqr(E);

    let two_D = fp_add(D, D);
    let X3 = fp_sub(F, two_D);

    let D_minus_X3 = fp_sub(D, X3);
    var eight_C = fp_add(C, C);
    eight_C = fp_add(eight_C, eight_C);
    eight_C = fp_add(eight_C, eight_C);
    let Y3 = fp_sub(fp_mul(E, D_minus_X3), eight_C);

    var Z3 = fp_mul(p.Y, p.Z);
    Z3 = fp_add(Z3, Z3);

    var r: G1J; r.X = X3; r.Y = Y3; r.Z = Z3; r.inf = 0u;
    return r;
}

fn g1_add(a: G1J, b: G1J) -> G1J {
    if (a.inf != 0u) { return b; }
    if (b.inf != 0u) { return a; }

    let Z1Z1 = fp_sqr(a.Z);
    let Z2Z2 = fp_sqr(b.Z);
    let U1 = fp_mul(a.X, Z2Z2);
    let U2 = fp_mul(b.X, Z1Z1);
    let S1 = fp_mul(fp_mul(a.Y, b.Z), Z2Z2);
    let S2 = fp_mul(fp_mul(b.Y, a.Z), Z1Z1);

    let H = fp_sub(U2, U1);
    if (u256_is_zero(H)) {
        if (u256_eq(S1, S2)) { return g1_double(a); }
        return g1_jac_zero();
    }

    let two_H = fp_add(H, H);
    let I = fp_sqr(two_H);
    let J = fp_mul(H, I);

    var r_ = fp_sub(S2, S1);
    r_ = fp_add(r_, r_);

    let V = fp_mul(U1, I);

    let X3 = fp_sub(fp_sub(fp_sqr(r_), J), fp_add(V, V));
    let Y3 = fp_sub(fp_mul(r_, fp_sub(V, X3)), fp_mul(fp_add(S1, S1), J));
    var Z3 = fp_sub(fp_sub(fp_sqr(fp_add(a.Z, b.Z)), Z1Z1), Z2Z2);
    Z3 = fp_mul(Z3, H);

    var out: G1J; out.X = X3; out.Y = Y3; out.Z = Z3; out.inf = 0u;
    return out;
}

fn g1_cmov(dst: G1J, src: G1J, cond: u32) -> G1J {
    var r = dst;
    let mask: u32 = 0u - (cond & 1u);   // 0 or 0xFFFFFFFF
    for (var i = 0u; i < 8u; i = i + 1u) {
        r.X[i] = dst.X[i] ^ (mask & (dst.X[i] ^ src.X[i]));
        r.Y[i] = dst.Y[i] ^ (mask & (dst.Y[i] ^ src.Y[i]));
        r.Z[i] = dst.Z[i] ^ (mask & (dst.Z[i] ^ src.Z[i]));
    }
    if ((cond & 1u) == 1u) { r.inf = src.inf; } else { r.inf = dst.inf; }
    return r;
}

// Constant-time Montgomery ladder over 256 bits.
fn g1_scalar_mul(p: G1A, k: array<u32, 8>) -> G1J {
    if (p.inf != 0u) { return g1_jac_zero(); }
    var R0 = g1_jac_zero();
    var R1 = g1_to_jac(p);

    for (var i = 255i; i >= 0; i = i - 1) {
        let ui = u32(i);
        let bit = (k[ui >> 5u] >> (ui & 31u)) & 1u;

        let sum  = g1_add(R0, R1);
        let dbl0 = g1_double(R0);
        let dbl1 = g1_double(R1);

        let next_R0 = g1_cmov(dbl0, sum,  bit);
        let next_R1 = g1_cmov(sum,  dbl1, bit);

        R0 = next_R0;
        R1 = next_R1;
    }
    return R0;
}

// =============================================================================
// SVDW map_to_curve
// =============================================================================

fn fp_sgn0(a: array<u32, 8>) -> u32 {
    let p = from_mont_p(a);
    return p[0] & 1u;
}

fn fp_g_x(x: array<u32, 8>) -> array<u32, 8> {
    let x2 = fp_sqr(x);
    let x3 = fp_mul(x2, x);
    return fp_add(x3, fp_three());
}

fn svdw_map(u_mont: array<u32, 8>) -> G1A {
    let ONE = BN_R;
    let Z   = to_mont_p(BN_SVDW_Z);
    let c1  = to_mont_p(BN_SVDW_C1);
    let c2  = to_mont_p(BN_SVDW_C2);
    let c3  = to_mont_p(BN_SVDW_C3);
    let c4  = to_mont_p(BN_SVDW_C4);

    var tv1 = fp_sqr(u_mont);
    tv1 = fp_mul(tv1, c1);
    let tv2 = fp_add(ONE, tv1);
    tv1 = fp_sub(ONE, tv1);
    var tv3 = fp_mul(tv1, tv2);
    tv3 = fp_inv(tv3);
    var tv4 = fp_mul(u_mont, tv1);
    tv4 = fp_mul(tv4, tv3);
    tv4 = fp_mul(tv4, c3);
    let x1 = fp_sub(c2, tv4);

    let gx1 = fp_g_x(x1);
    let s1  = fp_sqrt(gx1);
    let x2  = fp_add(c2, tv4);
    let gx2 = fp_g_x(x2);
    let s2  = fp_sqrt(gx2);

    var x3 = fp_sqr(tv2);
    x3 = fp_mul(x3, tv3);
    x3 = fp_sqr(x3);
    x3 = fp_mul(x3, c4);
    x3 = fp_add(x3, Z);

    var x: array<u32, 8>;
    if (s1.ok) { x = x1; } else { x = x3; }
    if (s2.ok && !s1.ok) { x = x2; }

    let gx = fp_g_x(x);
    let sy = fp_sqrt(gx);
    var y  = sy.v;
    if (fp_sgn0(u_mont) != fp_sgn0(y)) { y = fp_neg(y); }

    var r: G1A; r.x = x; r.y = y; r.inf = 0u;
    return r;
}

// =============================================================================
// Kernel I/O packing helpers
// =============================================================================
//
// Affine point lives in 18 x u32 (x[8] || y[8] || inf[2]) -- inf padded to two
// u32 to match the CUDA driver's 9 x u64 layout (each u64 = 2 x u32 LE).
// Field element / scalar = 8 x u32. Storage buffers are flat array<u32>.

@group(0) @binding(0) var<storage, read>       in_a:    array<u32>;
@group(0) @binding(1) var<storage, read>       in_b:    array<u32>;
@group(0) @binding(2) var<storage, read_write> out_buf: array<u32>;

fn load_field(off: u32) -> array<u32, 8> {
    var r: array<u32, 8>;
    for (var i = 0u; i < 8u; i = i + 1u) { r[i] = in_a[off + i]; }
    return r;
}

fn load_field_b(off: u32) -> array<u32, 8> {
    var r: array<u32, 8>;
    for (var i = 0u; i < 8u; i = i + 1u) { r[i] = in_b[off + i]; }
    return r;
}

fn store_field(off: u32, v: array<u32, 8>) {
    for (var i = 0u; i < 8u; i = i + 1u) { out_buf[off + i] = v[i]; }
}

fn load_aff_a(off: u32) -> G1A {
    var p: G1A;
    for (var i = 0u; i < 8u; i = i + 1u) { p.x[i] = in_a[off + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { p.y[i] = in_a[off + 8u + i]; }
    p.inf = in_a[off + 16u];
    return p;
}

fn load_aff_b(off: u32) -> G1A {
    var p: G1A;
    for (var i = 0u; i < 8u; i = i + 1u) { p.x[i] = in_b[off + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { p.y[i] = in_b[off + 8u + i]; }
    p.inf = in_b[off + 16u];
    return p;
}

fn store_aff(off: u32, p: G1A) {
    for (var i = 0u; i < 8u; i = i + 1u) { out_buf[off + i] = p.x[i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { out_buf[off + 8u + i] = p.y[i]; }
    out_buf[off + 16u] = p.inf;
    out_buf[off + 17u] = 0u;
}

// =============================================================================
// Kernels
// =============================================================================

@compute @workgroup_size(64)
fn k_g1_add(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    let stride = 18u;  // 8 + 8 + 2 (inf padded to u64)
    let off = i * stride;

    let A = load_aff_a(off);
    let B = load_aff_b(off);

    let Ja = g1_to_jac(A);
    let Jb = g1_to_jac(B);
    let S  = g1_add(Ja, Jb);
    let R  = g1_to_affine(S);

    store_aff(off, R);
}

@compute @workgroup_size(64)
fn k_g1_mul(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    let p_off = i * 18u;
    let s_off = i * 8u;

    let P = load_aff_a(p_off);
    var k: array<u32, 8>;
    for (var j = 0u; j < 8u; j = j + 1u) { k[j] = in_b[s_off + j]; }

    let S = g1_scalar_mul(P, k);
    let R = g1_to_affine(S);

    store_aff(p_off, R);
}

@compute @workgroup_size(64)
fn k_svdw(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    let in_off = i * 8u;
    let out_off = i * 18u;

    let u = load_field(in_off);
    let R = svdw_map(u);
    store_aff(out_off, R);
}

@compute @workgroup_size(64)
fn k_fp_mul(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    let off = i * 8u;
    let A = load_field(off);
    let B = load_field_b(off);
    let R = fp_mul(A, B);
    store_field(off, R);
}

// =============================================================================
// Fp2 = Fp[u]/(u^2 + 1) -- Karatsuba mul (matches CPU bn254_fp2.hpp:fp2_mul).
// Layout per Fp2: a0 (8 u32) || a1 (8 u32) -- 16 u32 per element.
// =============================================================================

struct F2 { a0: array<u32, 8>, a1: array<u32, 8> };

fn f2_load_a(off: u32) -> F2 {
    var r: F2;
    for (var i = 0u; i < 8u; i = i + 1u) { r.a0[i] = in_a[off + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { r.a1[i] = in_a[off + 8u + i]; }
    return r;
}
fn f2_load_b(off: u32) -> F2 {
    var r: F2;
    for (var i = 0u; i < 8u; i = i + 1u) { r.a0[i] = in_b[off + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { r.a1[i] = in_b[off + 8u + i]; }
    return r;
}
fn f2_store(off: u32, v: F2) {
    for (var i = 0u; i < 8u; i = i + 1u) { out_buf[off + i] = v.a0[i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { out_buf[off + 8u + i] = v.a1[i]; }
}

fn fp2_mul(x: F2, y: F2) -> F2 {
    let a = fp_mul(fp_add(x.a0, x.a1), fp_add(y.a0, y.a1));
    let b = fp_mul(x.a0, y.a0);
    let c = fp_mul(x.a1, y.a1);
    var r: F2;
    r.a1 = fp_sub(fp_sub(a, b), c);
    r.a0 = fp_sub(b, c);
    return r;
}

@compute @workgroup_size(64)
fn k_fp2_mul(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    let off = i * 16u;
    let A = f2_load_a(off);
    let B = f2_load_b(off);
    let R = fp2_mul(A, B);
    f2_store(off, R);
}

// =============================================================================
// Fp6 / Fp12 mul -- Algorithm transliteration of CPU bn254_fp{6,12}.hpp.
// Fp12 layout: c0 (Fp6) || c1 (Fp6); Fp6 = b0 (Fp2) || b1 (Fp2) || b2 (Fp2).
// 12 x Fp2 per Fp12 -> 96 x u32.
// =============================================================================

struct F6  { b0: F2, b1: F2, b2: F2 };
struct F12 { c0: F6, c1: F6 };

fn fp2_zero() -> F2 {
    var r: F2;
    for (var i = 0u; i < 8u; i = i + 1u) { r.a0[i] = 0u; r.a1[i] = 0u; }
    return r;
}
fn fp2_add(x: F2, y: F2) -> F2 {
    var r: F2; r.a0 = fp_add(x.a0, y.a0); r.a1 = fp_add(x.a1, y.a1); return r;
}
fn fp2_sub(x: F2, y: F2) -> F2 {
    var r: F2; r.a0 = fp_sub(x.a0, y.a0); r.a1 = fp_sub(x.a1, y.a1); return r;
}
fn fp2_neg_local(x: F2) -> F2 {
    var r: F2; r.a0 = fp_neg(x.a0); r.a1 = fp_neg(x.a1); return r;
}

// (a0 + a1*u) * (9 + u): 9*a0 = 8*a0 + a0.
fn fp2_mul_by_nonres(x: F2) -> F2 {
    var t0 = fp_add(x.a0, x.a0);
    t0 = fp_add(t0, t0);
    t0 = fp_add(t0, t0);
    var t1 = fp_add(x.a1, x.a1);
    t1 = fp_add(t1, t1);
    t1 = fp_add(t1, t1);
    var r: F2;
    r.a0 = fp_sub(fp_add(t0, x.a0), x.a1);
    r.a1 = fp_add(fp_add(t1, x.a1), x.a0);
    return r;
}

fn fp6_add(x: F6, y: F6) -> F6 {
    var r: F6; r.b0 = fp2_add(x.b0, y.b0); r.b1 = fp2_add(x.b1, y.b1); r.b2 = fp2_add(x.b2, y.b2); return r;
}
fn fp6_sub(x: F6, y: F6) -> F6 {
    var r: F6; r.b0 = fp2_sub(x.b0, y.b0); r.b1 = fp2_sub(x.b1, y.b1); r.b2 = fp2_sub(x.b2, y.b2); return r;
}
fn fp6_mul_by_nonres(x: F6) -> F6 {
    var r: F6; r.b0 = fp2_mul_by_nonres(x.b2); r.b1 = x.b0; r.b2 = x.b1; return r;
}

fn fp6_mul(x: F6, y: F6) -> F6 {
    let t0 = fp2_mul(x.b0, y.b0);
    let t1 = fp2_mul(x.b1, y.b1);
    let t2 = fp2_mul(x.b2, y.b2);

    var c0 = fp2_add(x.b1, x.b2);
    var tmp = fp2_add(y.b1, y.b2);
    c0 = fp2_mul(c0, tmp);
    c0 = fp2_sub(c0, t1);
    c0 = fp2_sub(c0, t2);
    c0 = fp2_mul_by_nonres(c0);
    c0 = fp2_add(c0, t0);

    var c1 = fp2_add(x.b0, x.b1);
    tmp = fp2_add(y.b0, y.b1);
    c1 = fp2_mul(c1, tmp);
    c1 = fp2_sub(c1, t0);
    c1 = fp2_sub(c1, t1);
    let t2_nr = fp2_mul_by_nonres(t2);
    c1 = fp2_add(c1, t2_nr);

    var c2 = fp2_add(x.b0, x.b2);
    tmp = fp2_add(y.b0, y.b2);
    c2 = fp2_mul(c2, tmp);
    c2 = fp2_sub(c2, t0);
    c2 = fp2_sub(c2, t2);
    c2 = fp2_add(c2, t1);

    var r: F6; r.b0 = c0; r.b1 = c1; r.b2 = c2; return r;
}

fn fp12_mul(x: F12, y: F12) -> F12 {
    var a = fp6_add(x.c0, x.c1);
    var b = fp6_add(y.c0, y.c1);
    a = fp6_mul(a, b);
    b = fp6_mul(x.c0, y.c0);
    let c = fp6_mul(x.c1, y.c1);
    var r: F12;
    r.c1 = fp6_sub(fp6_sub(a, b), c);
    r.c0 = fp6_add(fp6_mul_by_nonres(c), b);
    return r;
}

fn f12_load_a(off: u32) -> F12 {
    var r: F12;
    for (var i = 0u; i < 8u; i = i + 1u) { r.c0.b0.a0[i] = in_a[off +  0u + i]; r.c0.b0.a1[i] = in_a[off +  8u + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { r.c0.b1.a0[i] = in_a[off + 16u + i]; r.c0.b1.a1[i] = in_a[off + 24u + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { r.c0.b2.a0[i] = in_a[off + 32u + i]; r.c0.b2.a1[i] = in_a[off + 40u + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { r.c1.b0.a0[i] = in_a[off + 48u + i]; r.c1.b0.a1[i] = in_a[off + 56u + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { r.c1.b1.a0[i] = in_a[off + 64u + i]; r.c1.b1.a1[i] = in_a[off + 72u + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { r.c1.b2.a0[i] = in_a[off + 80u + i]; r.c1.b2.a1[i] = in_a[off + 88u + i]; }
    return r;
}
fn f12_load_b(off: u32) -> F12 {
    var r: F12;
    for (var i = 0u; i < 8u; i = i + 1u) { r.c0.b0.a0[i] = in_b[off +  0u + i]; r.c0.b0.a1[i] = in_b[off +  8u + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { r.c0.b1.a0[i] = in_b[off + 16u + i]; r.c0.b1.a1[i] = in_b[off + 24u + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { r.c0.b2.a0[i] = in_b[off + 32u + i]; r.c0.b2.a1[i] = in_b[off + 40u + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { r.c1.b0.a0[i] = in_b[off + 48u + i]; r.c1.b0.a1[i] = in_b[off + 56u + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { r.c1.b1.a0[i] = in_b[off + 64u + i]; r.c1.b1.a1[i] = in_b[off + 72u + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { r.c1.b2.a0[i] = in_b[off + 80u + i]; r.c1.b2.a1[i] = in_b[off + 88u + i]; }
    return r;
}
fn f12_store(off: u32, v: F12) {
    for (var i = 0u; i < 8u; i = i + 1u) { out_buf[off +  0u + i] = v.c0.b0.a0[i]; out_buf[off +  8u + i] = v.c0.b0.a1[i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { out_buf[off + 16u + i] = v.c0.b1.a0[i]; out_buf[off + 24u + i] = v.c0.b1.a1[i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { out_buf[off + 32u + i] = v.c0.b2.a0[i]; out_buf[off + 40u + i] = v.c0.b2.a1[i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { out_buf[off + 48u + i] = v.c1.b0.a0[i]; out_buf[off + 56u + i] = v.c1.b0.a1[i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { out_buf[off + 64u + i] = v.c1.b1.a0[i]; out_buf[off + 72u + i] = v.c1.b1.a1[i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { out_buf[off + 80u + i] = v.c1.b2.a0[i]; out_buf[off + 88u + i] = v.c1.b2.a1[i]; }
}

@compute @workgroup_size(32)
fn k_fp12_mul(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    let off = i * 96u;
    let A = f12_load_a(off);
    let B = f12_load_b(off);
    let R = fp12_mul(A, B);
    f12_store(off, R);
}

// =============================================================================
// Frobenius constants -- emitted from CPU body by bn254_gen_pairing_constants.
// WGSL has no native u64; each u64 limb is split into a (lo, hi) pair of u32.
// Single producer is bn254/cpp/bn254_pairing.cpp; CPU/GPU drift fails the
// determinism test by construction.
// =============================================================================

// NR1Power_k for k=1..5 -- 5 Fp2 elements (a0, a1).
const K_NR1P1_A0 : array<u32, 8> = array<u32, 8>(
    0x33144907u, 0xaf9ba696u, 0x87afb78au, 0xca6b1d73u,
    0xf08a2087u, 0x11bded5eu, 0x1a1f3a7cu, 0x02f34d75u
);
const K_NR1P1_A1 : array<u32, 8> = array<u32, 8>(
    0x4c492d72u, 0xa222ae23u, 0x565de15bu, 0xd00f02a4u,
    0x53dfc926u, 0xdc2ff3a2u, 0xb3899551u, 0x10a75716u
);
const K_NR1P2_A0 : array<u32, 8> = array<u32, 8>(
    0x4563ab30u, 0xb5773b10u, 0xa9aa6454u, 0x347f91c8u,
    0x242e0991u, 0x7a007127u, 0x118214ecu, 0x1956bcd8u
);
const K_NR1P2_A1 : array<u32, 8> = array<u32, 8>(
    0xa0aa4757u, 0x6e849f1eu, 0x89f89141u, 0xaa1c7b6du,
    0xfae0ca3au, 0xb6e713cdu, 0x4e82ebc3u, 0x26694fbbu
);
const K_NR1P3_A0 : array<u32, 8> = array<u32, 8>(
    0x2936b629u, 0xe4bbdd0cu, 0xe133bacbu, 0xbb30f162u,
    0xf9645366u, 0x31a9d1b6u, 0xa500f8ddu, 0x253570beu
);
const K_NR1P3_A1 : array<u32, 8> = array<u32, 8>(
    0x5ffe77c7u, 0xa1d77ce4u, 0x7826d1dbu, 0x07affd11u,
    0xbb7edc6bu, 0x6d16bd27u, 0x85defeccu, 0x2c872002u
);
const K_NR1P4_A0 : array<u32, 8> = array<u32, 8>(
    0x843abe92u, 0x7361d77fu, 0x273411fbu, 0xa5bb2bd3u,
    0x4b3e2399u, 0x9c941f31u, 0xbb9fd3ecu, 0x15df9cddu
);
const K_NR1P4_A1 : array<u32, 8> = array<u32, 8>(
    0x4bd8c949u, 0x5dddfd15u, 0xa4445b60u, 0x62cb29a5u,
    0x0c7dd2b9u, 0x37bc870au, 0x3171f0fdu, 0x24830a9du
);
const K_NR1P5_A0 : array<u32, 8> = array<u32, 8>(
    0x41690fe7u, 0xc970692fu, 0x27694b0bu, 0xe2403421u,
    0x83c459e8u, 0x32bee66bu, 0x0ab08841u, 0x12aabcedu
);
const K_NR1P5_A1 : array<u32, 8> = array<u32, 8>(
    0x40aebfa9u, 0x0d485d23u, 0xab2fcc57u, 0x05193418u,
    0x8a4910f5u, 0xd3b0a40bu, 0x35d2925au, 0x2f21ebb5u
);

// NR2Power_k -- Fp scalars (single U256 each).
const K_NR2P1 : array<u32, 8> = array<u32, 8>(
    0x00fa1bf2u, 0xca8d8005u, 0x68b39769u, 0xf0c5d614u,
    0xad0d4418u, 0x0e201271u, 0xbad856e6u, 0x04290f65u
);
const K_NR2P2 : array<u32, 8> = array<u32, 8>(
    0x13e80b9cu, 0x3350c88eu, 0xdb5e56b9u, 0x7dce557cu,
    0xb615564au, 0x6001b4b8u, 0x020217e0u, 0x2682e617u
);
const K_NR2P3 : array<u32, 8> = array<u32, 8>(
    0x12edefaau, 0x68c34889u, 0x72aabf4fu, 0x8d087f68u,
    0x09081231u, 0x51e1a247u, 0x4729c0fau, 0x2259d6b1u
);
const K_NR2P4 : array<u32, 8> = array<u32, 8>(
    0xd782e155u, 0x71930c11u, 0xffbe3323u, 0xa6bb947cu,
    0xd4741444u, 0xaa303344u, 0x26594943u, 0x2c3b3f0du
);
const K_NR2P5 : array<u32, 8> = array<u32, 8>(
    0xc494f1abu, 0x08cfc388u, 0x8d1373d4u, 0x19b31514u,
    0xcb6c0213u, 0x584e90fdu, 0xdf2f8849u, 0x09e1685bu
);

// NR3Power_k -- Fp2 elements.
const K_NR3P1_A0 : array<u32, 8> = array<u32, 8>(
    0x4e46d97du, 0x36531618u, 0xd4c96d9fu, 0x0af7129eu,
    0xca1009b5u, 0x659da72fu, 0x83a20d23u, 0x08116d89u
);
const K_NR3P1_A1 : array<u32, 8> = array<u32, 8>(
    0xc39c1939u, 0xb1df4af7u, 0x8a73bf7fu, 0x3d9f0287u,
    0x8caf0ae0u, 0x9b222092u, 0xeff054a6u, 0x26684515u
);
const K_NR3P2_A0 : array<u32, 8> = array<u32, 8>(
    0x16ad6badu, 0xc9af22f7u, 0x4aa662b2u, 0xb311782au,
    0xe248c7f4u, 0x19eeaf64u, 0xe3439f82u, 0x20273e77u
);
const K_NR3P2_A1 : array<u32, 8> = array<u32, 8>(
    0xf7ce93acu, 0xacc02860u, 0x7ba76b4cu, 0x3933d581u,
    0x446c8467u, 0x69e6188bu, 0x4417cc55u, 0x0a46036du
);
const K_NR3P3_A0 : array<u32, 8> = array<u32, 8>(
    0xaf46471eu, 0x5764af0au, 0x873e0fc1u, 0xdc50792eu,
    0x881d04f6u, 0x86a673ffu, 0x3c30a74cu, 0x0b2eddb4u
);
const K_NR3P3_A1 : array<u32, 8> = array<u32, 8>(
    0x787e8580u, 0x9a490f32u, 0xf04af8b1u, 0x8fd16d7fu,
    0xc6027bf2u, 0x4b39888eu, 0x5b52a15du, 0x03dd2e70u
);
const K_NR3P4_A0 : array<u32, 8> = array<u32, 8>(
    0x7b6762dfu, 0x448a93a5u, 0x28fdeadfu, 0xbfd62df5u,
    0x0e9bd47au, 0xd858f5d0u, 0x3476ec58u, 0x06b03d4du
);
const K_NR3P4_A1 : array<u32, 8> = array<u32, 8>(
    0xbcc936d1u, 0x2b19daf4u, 0x56f4299fu, 0xa1a54e7au,
    0x5adeaef1u, 0xb533eee0u, 0x84dda0b2u, 0x170c812bu
);
const K_NR3P5_A0 : array<u32, 8> = array<u32, 8>(
    0x75cf559fu, 0xe0bc4b22u, 0xc154e60fu, 0xc238b945u,
    0x929a7d5eu, 0x803982a5u, 0xf7e4a37eu, 0x15ce052du
);
const K_NR3P5_A1 : array<u32, 8> = array<u32, 8>(
    0xbf3799a7u, 0x2d28efbdu, 0x1ad60773u, 0x9b097e3cu,
    0xaf4a535bu, 0x982d4113u, 0xe3056063u, 0x24e18991u
);

// =============================================================================
// Fp2 extras: zero, one, sqr, conjugate, neg, double, mul_by_fp, mul_by_nonres_inv,
// inv, halve. Order/algorithm mirrors bn254/cpp/bn254_fp2.hpp + bn254_pairing.cuh.
// =============================================================================

fn fp2_one() -> F2 {
    var r: F2;
    r.a0 = BN_R;
    for (var i = 0u; i < 8u; i = i + 1u) { r.a1[i] = 0u; }
    return r;
}

fn fp2_is_zero(x: F2) -> bool { return u256_is_zero(x.a0) && u256_is_zero(x.a1); }

fn fp2_double(x: F2) -> F2 {
    var r: F2; r.a0 = fp_add(x.a0, x.a0); r.a1 = fp_add(x.a1, x.a1); return r;
}

fn fp2_conjugate(x: F2) -> F2 {
    var r: F2; r.a0 = x.a0; r.a1 = fp_neg(x.a1); return r;
}

fn fp2_mul_by_fp(x: F2, y: array<u32, 8>) -> F2 {
    var r: F2; r.a0 = fp_mul(x.a0, y); r.a1 = fp_mul(x.a1, y); return r;
}

fn fp2_sqr(x: F2) -> F2 {
    let a = fp_mul(fp_add(x.a0, x.a1), fp_sub(x.a0, x.a1));
    let b = fp_mul(x.a0, x.a1);
    var r: F2; r.a0 = a; r.a1 = fp_add(b, b);
    return r;
}

fn fp2_inv(x: F2) -> F2 {
    let t0 = fp_sqr(x.a0);
    let t1 = fp_sqr(x.a1);
    let t  = fp_add(t0, t1);
    let ti = fp_inv(t);
    var r: F2;
    r.a0 = fp_mul(x.a0, ti);
    r.a1 = fp_neg(fp_mul(x.a1, ti));
    return r;
}

// Multiply by (9+u)^-1. Used inside mul_b_twist (line eval) -- amortised cost.
fn fp2_mul_by_nonres_inv(x: F2) -> F2 {
    var nr: F2;
    nr.a0 = to_mont_p(array<u32, 8>(9u, 0u, 0u, 0u, 0u, 0u, 0u, 0u));
    nr.a1 = BN_R;  // Montgomery 1
    let inv_nr = fp2_inv(nr);
    return fp2_mul(x, inv_nr);
}

// fp_halve: (a + p)/2 if a odd else a/2. Algorithm-equivalent to CPU
// bn254_pairing.cpp:fp_halve.
fn fp_halve(v: array<u32, 8>) -> array<u32, 8> {
    var r = v;
    if ((r[0] & 1u) == 1u) {
        var t: array<u32, 8>;
        let c = u256_add(r, BN_P, &t);
        r = t;
        // Combined right-shift by 1 across 8 limbs, with c filling top.
        for (var i = 0u; i < 7u; i = i + 1u) {
            r[i] = (r[i] >> 1u) | ((r[i + 1u] & 1u) << 31u);
        }
        r[7] = (r[7] >> 1u) | (c << 31u);
    } else {
        for (var i = 0u; i < 7u; i = i + 1u) {
            r[i] = (r[i] >> 1u) | ((r[i + 1u] & 1u) << 31u);
        }
        r[7] = r[7] >> 1u;
    }
    return r;
}

fn fp2_halve(x: F2) -> F2 {
    var r: F2; r.a0 = fp_halve(x.a0); r.a1 = fp_halve(x.a1); return r;
}

// b-twist coefficient: 3 * (9+u)^-1.
fn mul_b_twist(x: F2) -> F2 {
    let res = fp2_mul_by_nonres_inv(x);
    return fp2_add(fp2_double(res), res);
}

// Mul by NR1Power_k: an Fp2 lookup constant, materialise as F2.
fn mul_nr1(x: F2, nr_a0: array<u32, 8>, nr_a1: array<u32, 8>) -> F2 {
    var nr: F2; nr.a0 = nr_a0; nr.a1 = nr_a1;
    return fp2_mul(x, nr);
}

// Mul by NR2Power_k: an Fp scalar applied to both Fp2 limbs.
fn mul_nr2(x: F2, s: array<u32, 8>) -> F2 {
    var r: F2; r.a0 = fp_mul(x.a0, s); r.a1 = fp_mul(x.a1, s); return r;
}

// =============================================================================
// Fp6 extras: zero, one, neg, double, sqr, inv, mul_by_01, mul_by_fp2.
// =============================================================================

fn fp6_zero() -> F6 {
    var r: F6; r.b0 = fp2_zero(); r.b1 = fp2_zero(); r.b2 = fp2_zero(); return r;
}
fn fp6_one() -> F6 {
    var r: F6; r.b0 = fp2_one(); r.b1 = fp2_zero(); r.b2 = fp2_zero(); return r;
}
fn fp6_neg(x: F6) -> F6 {
    var r: F6; r.b0 = fp2_neg_local(x.b0); r.b1 = fp2_neg_local(x.b1); r.b2 = fp2_neg_local(x.b2); return r;
}
fn fp6_double(x: F6) -> F6 {
    var r: F6; r.b0 = fp2_double(x.b0); r.b1 = fp2_double(x.b1); r.b2 = fp2_double(x.b2); return r;
}

fn fp6_sqr(x: F6) -> F6 {
    var c4 = fp2_mul(x.b0, x.b1);
    c4 = fp2_double(c4);
    let c5 = fp2_sqr(x.b2);
    var c1 = fp2_mul_by_nonres(c5);
    c1 = fp2_add(c1, c4);
    let c2 = fp2_sub(c4, c5);
    let c3 = fp2_sqr(x.b0);
    var c4b = fp2_sub(x.b0, x.b1);
    c4b = fp2_add(c4b, x.b2);
    var c5b = fp2_mul(x.b1, x.b2);
    c5b = fp2_double(c5b);
    c4b = fp2_sqr(c4b);
    var c0 = fp2_mul_by_nonres(c5b);
    c0 = fp2_add(c0, c3);

    var z2 = fp2_add(c2, c4b);
    z2 = fp2_add(z2, c5b);
    z2 = fp2_sub(z2, c3);

    var r: F6; r.b0 = c0; r.b1 = c1; r.b2 = z2; return r;
}

fn fp6_inv(x: F6) -> F6 {
    let t0 = fp2_sqr(x.b0);
    let t1 = fp2_sqr(x.b1);
    let t2 = fp2_sqr(x.b2);
    let t3 = fp2_mul(x.b0, x.b1);
    let t4 = fp2_mul(x.b0, x.b2);
    let t5 = fp2_mul(x.b1, x.b2);

    var c0 = fp2_mul_by_nonres(t5);
    c0 = fp2_neg_local(c0);
    c0 = fp2_add(c0, t0);

    var c1 = fp2_mul_by_nonres(t2);
    c1 = fp2_sub(c1, t3);

    let c2 = fp2_sub(t1, t4);

    var t6 = fp2_mul(x.b0, c0);
    let d1 = fp2_mul(x.b2, c1);
    let d2 = fp2_mul(x.b1, c2);
    var d  = fp2_add(d1, d2);
    d = fp2_mul_by_nonres(d);
    t6 = fp2_add(t6, d);
    let t6_inv = fp2_inv(t6);

    var r: F6;
    r.b0 = fp2_mul(c0, t6_inv);
    r.b1 = fp2_mul(c1, t6_inv);
    r.b2 = fp2_mul(c2, t6_inv);
    return r;
}

fn fp6_mul_by_01(z: F6, c0: F2, c1: F2) -> F6 {
    let a = fp2_mul(z.b0, c0);
    let b = fp2_mul(z.b1, c1);

    var tmp = fp2_add(z.b1, z.b2);
    var t0 = fp2_mul(c1, tmp);
    t0 = fp2_sub(t0, b);
    t0 = fp2_mul_by_nonres(t0);
    t0 = fp2_add(t0, a);

    tmp = fp2_add(z.b0, z.b2);
    var t2 = fp2_mul(c0, tmp);
    t2 = fp2_sub(t2, a);
    t2 = fp2_add(t2, b);

    var t1 = fp2_add(c0, c1);
    tmp = fp2_add(z.b0, z.b1);
    t1 = fp2_mul(t1, tmp);
    t1 = fp2_sub(t1, a);
    t1 = fp2_sub(t1, b);

    var r: F6; r.b0 = t0; r.b1 = t1; r.b2 = t2; return r;
}

fn fp6_mul_by_fp2(z: F6, y: F2) -> F6 {
    var r: F6;
    r.b0 = fp2_mul(z.b0, y);
    r.b1 = fp2_mul(z.b1, y);
    r.b2 = fp2_mul(z.b2, y);
    return r;
}

// =============================================================================
// Fp12 extras: zero, one, sqr, conjugate, inv, mul_by_034, mul_034_by_034,
// mul_by_01234.
// =============================================================================

fn fp12_zero() -> F12 {
    var r: F12; r.c0 = fp6_zero(); r.c1 = fp6_zero(); return r;
}
fn fp12_one() -> F12 {
    var r: F12; r.c0 = fp6_one(); r.c1 = fp6_zero(); return r;
}

fn fp12_is_one(z: F12) -> bool {
    let one = fp12_one();
    return fp2_is_zero(z.c1.b0) && fp2_is_zero(z.c1.b1) && fp2_is_zero(z.c1.b2)
        && fp2_is_zero(z.c0.b1) && fp2_is_zero(z.c0.b2)
        && u256_is_zero(z.c0.b0.a1)
        && u256_eq(z.c0.b0.a0, one.c0.b0.a0);
}

fn fp12_conjugate(x: F12) -> F12 {
    var r: F12; r.c0 = x.c0; r.c1 = fp6_neg(x.c1); return r;
}

fn fp12_sqr(x: F12) -> F12 {
    var c0 = fp6_sub(x.c0, x.c1);
    var c3 = fp6_mul_by_nonres(x.c1);
    c3 = fp6_neg(c3);
    c3 = fp6_add(x.c0, c3);
    let c2 = fp6_mul(x.c0, x.c1);
    c0 = fp6_mul(c0, c3);
    c0 = fp6_add(c0, c2);
    let r1 = fp6_double(c2);
    let c2b = fp6_mul_by_nonres(c2);
    let r0 = fp6_add(c0, c2b);
    var r: F12; r.c0 = r0; r.c1 = r1; return r;
}

fn fp12_inv(x: F12) -> F12 {
    let t0 = fp6_sqr(x.c0);
    let t1 = fp6_sqr(x.c1);
    let tmp = fp6_mul_by_nonres(t1);
    let t0b = fp6_sub(t0, tmp);
    let t0_inv = fp6_inv(t0b);
    var r: F12;
    r.c0 = fp6_mul(x.c0, t0_inv);
    r.c1 = fp6_neg(fp6_mul(x.c1, t0_inv));
    return r;
}

// Mul by sparse line element (c0, c3, c4) -- the standard 034-form line eval.
fn fp12_mul_by_034(z: F12, c0: F2, c3: F2, c4: F2) -> F12 {
    let a = fp6_mul_by_fp2(z.c0, c0);
    var b = z.c1;
    b = fp6_mul_by_01(b, c3, c4);

    let d0 = fp2_add(c0, c3);
    var d = fp6_add(z.c0, z.c1);
    d = fp6_mul_by_01(d, d0, c4);

    var r1 = fp6_add(a, b);
    r1 = fp6_neg(r1);
    r1 = fp6_add(r1, d);
    var r0 = fp6_mul_by_nonres(b);
    r0 = fp6_add(r0, a);
    var r: F12; r.c0 = r0; r.c1 = r1; return r;
}

struct Fp12Sparse5 { v00: F2, v01: F2, v02: F2, v10: F2, v11: F2 };

// Multiply two sparse 034-form line elements. Result is sparse-5
// (c0.b0, c0.b1, c0.b2, c1.b0, c1.b1) with c1.b2 = 0.
fn fp12_mul_034_by_034(d0: F2, d3: F2, d4: F2, c0: F2, c3: F2, c4: F2) -> Fp12Sparse5 {
    let x0 = fp2_mul(c0, d0);
    let x3 = fp2_mul(c3, d3);
    let x4 = fp2_mul(c4, d4);

    var tmp = fp2_add(c0, c4);
    var x04 = fp2_add(d0, d4);
    x04 = fp2_mul(x04, tmp);
    x04 = fp2_sub(x04, x0);
    x04 = fp2_sub(x04, x4);

    tmp = fp2_add(c0, c3);
    var x03 = fp2_add(d0, d3);
    x03 = fp2_mul(x03, tmp);
    x03 = fp2_sub(x03, x0);
    x03 = fp2_sub(x03, x3);

    tmp = fp2_add(c3, c4);
    var x34 = fp2_add(d3, d4);
    x34 = fp2_mul(x34, tmp);
    x34 = fp2_sub(x34, x3);
    x34 = fp2_sub(x34, x4);

    var z00 = fp2_mul_by_nonres(x4);
    z00 = fp2_add(z00, x0);
    var r: Fp12Sparse5;
    r.v00 = z00; r.v01 = x3; r.v02 = x34; r.v10 = x03; r.v11 = x04;
    return r;
}

// Generic Fp12 multiplied by sparse-5 (folded product of two 034 line evals).
fn fp12_mul_by_01234(z: F12, x: Fp12Sparse5) -> F12 {
    var c0_part: F6; c0_part.b0 = x.v00; c0_part.b1 = x.v01; c0_part.b2 = x.v02;
    var c1_part: F6; c1_part.b0 = x.v10; c1_part.b1 = x.v11; c1_part.b2 = fp2_zero();

    var a = fp6_add(z.c0, z.c1);
    var b = fp6_add(c0_part, c1_part);
    a = fp6_mul(a, b);

    b = fp6_mul(z.c0, c0_part);
    let c = fp6_mul_by_01(z.c1, x.v10, x.v11);

    var r1 = fp6_sub(a, b);
    r1 = fp6_sub(r1, c);

    var r0 = fp6_mul_by_nonres(c);
    r0 = fp6_add(r0, b);

    var r: F12; r.c0 = r0; r.c1 = r1; return r;
}

// =============================================================================
// Frobenius operators (Algorithms 28-30, eprint 2010/354).
// =============================================================================

fn frobenius(x: F12) -> F12 {
    var t0 = fp2_conjugate(x.c0.b0);
    var t1 = fp2_conjugate(x.c0.b1);
    var t2 = fp2_conjugate(x.c0.b2);
    var t3 = fp2_conjugate(x.c1.b0);
    var t4 = fp2_conjugate(x.c1.b1);
    var t5 = fp2_conjugate(x.c1.b2);

    t1 = mul_nr1(t1, K_NR1P2_A0, K_NR1P2_A1);
    t2 = mul_nr1(t2, K_NR1P4_A0, K_NR1P4_A1);
    t3 = mul_nr1(t3, K_NR1P1_A0, K_NR1P1_A1);
    t4 = mul_nr1(t4, K_NR1P3_A0, K_NR1P3_A1);
    t5 = mul_nr1(t5, K_NR1P5_A0, K_NR1P5_A1);

    var z: F12;
    z.c0.b0 = t0; z.c0.b1 = t1; z.c0.b2 = t2;
    z.c1.b0 = t3; z.c1.b1 = t4; z.c1.b2 = t5;
    return z;
}

fn frobenius_sq(x: F12) -> F12 {
    var z: F12;
    z.c0.b0 = x.c0.b0;
    z.c0.b1 = mul_nr2(x.c0.b1, K_NR2P2);
    z.c0.b2 = mul_nr2(x.c0.b2, K_NR2P4);
    z.c1.b0 = mul_nr2(x.c1.b0, K_NR2P1);
    z.c1.b1 = mul_nr2(x.c1.b1, K_NR2P3);
    z.c1.b2 = mul_nr2(x.c1.b2, K_NR2P5);
    return z;
}

fn frobenius_cube(x: F12) -> F12 {
    var t0 = fp2_conjugate(x.c0.b0);
    var t1 = fp2_conjugate(x.c0.b1);
    var t2 = fp2_conjugate(x.c0.b2);
    var t3 = fp2_conjugate(x.c1.b0);
    var t4 = fp2_conjugate(x.c1.b1);
    var t5 = fp2_conjugate(x.c1.b2);

    t1 = mul_nr1(t1, K_NR3P2_A0, K_NR3P2_A1);
    t2 = mul_nr1(t2, K_NR3P4_A0, K_NR3P4_A1);
    t3 = mul_nr1(t3, K_NR3P1_A0, K_NR3P1_A1);
    t4 = mul_nr1(t4, K_NR3P3_A0, K_NR3P3_A1);
    t5 = mul_nr1(t5, K_NR3P5_A0, K_NR3P5_A1);

    var z: F12;
    z.c0.b0 = t0; z.c0.b1 = t1; z.c0.b2 = t2;
    z.c1.b0 = t3; z.c1.b1 = t4; z.c1.b2 = t5;
    return z;
}

// =============================================================================
// Granger-Scott cyclotomic squaring (eprint 2009/565 §3.2).
// =============================================================================

fn cyclotomic_sqr(x: F12) -> F12 {
    let t0 = fp2_sqr(x.c1.b1);
    let t1 = fp2_sqr(x.c0.b0);
    let t6 = fp2_sub(fp2_sub(fp2_sqr(fp2_add(x.c1.b1, x.c0.b0)), t0), t1);
    let t2 = fp2_sqr(x.c0.b2);
    let t3 = fp2_sqr(x.c1.b0);
    let t7 = fp2_sub(fp2_sub(fp2_sqr(fp2_add(x.c0.b2, x.c1.b0)), t2), t3);
    let t4 = fp2_sqr(x.c1.b2);
    let t5 = fp2_sqr(x.c0.b1);
    var t8 = fp2_sub(fp2_sub(fp2_sqr(fp2_add(x.c1.b2, x.c0.b1)), t4), t5);
    t8 = fp2_mul_by_nonres(t8);

    let t0b = fp2_add(fp2_mul_by_nonres(t0), t1);
    let t2b = fp2_add(fp2_mul_by_nonres(t2), t3);
    let t4b = fp2_add(fp2_mul_by_nonres(t4), t5);

    var z: F12;
    z.c0.b0 = fp2_add(fp2_double(fp2_sub(t0b, x.c0.b0)), t0b);
    z.c0.b1 = fp2_add(fp2_double(fp2_sub(t2b, x.c0.b1)), t2b);
    z.c0.b2 = fp2_add(fp2_double(fp2_sub(t4b, x.c0.b2)), t4b);
    z.c1.b0 = fp2_add(fp2_double(fp2_add(t8,  x.c1.b0)), t8);
    z.c1.b1 = fp2_add(fp2_double(fp2_add(t6,  x.c1.b1)), t6);
    z.c1.b2 = fp2_add(fp2_double(fp2_add(t7,  x.c1.b2)), t7);
    return z;
}

fn cyclotomic_n_sqr(z_in: F12, n: i32) -> F12 {
    var z = z_in;
    for (var i = 0i; i < n; i = i + 1) { z = cyclotomic_sqr(z); }
    return z;
}

// =============================================================================
// expt: x^t with t = 4965661367192848881 (BN254 trace t = 6x+2).
// gnark-crypto addition chain, byte-equal to CPU oracle.
// =============================================================================

fn expt(x: F12) -> F12 {
    let t3a = cyclotomic_sqr(x);
    let t5a = cyclotomic_sqr(t3a);
    let result_a = cyclotomic_sqr(t5a);
    let t0a = cyclotomic_sqr(result_a);
    let t2a = fp12_mul(x, t0a);
    let t0b = fp12_mul(t3a, t2a);
    let t1a = fp12_mul(x, t0b);
    let t4a = fp12_mul(result_a, t2a);
    var t6a = cyclotomic_sqr(t2a);
    let t1b = fp12_mul(t0b, t1a);
    let t0c = fp12_mul(t3a, t1b);

    t6a = cyclotomic_n_sqr(t6a, 6);
    let t5b = fp12_mul(t5a, t6a);
    let t5c = fp12_mul(t4a, t5b);

    let t5d = cyclotomic_n_sqr(t5c, 7);
    let t4b = fp12_mul(t4a, t5d);

    let t4c = cyclotomic_n_sqr(t4b, 8);
    let t4d = fp12_mul(t0c, t4c);
    let t3b = fp12_mul(t3a, t4d);

    let t3c = cyclotomic_n_sqr(t3b, 6);
    let t2b = fp12_mul(t2a, t3c);

    let t2c = cyclotomic_n_sqr(t2b, 8);
    let t2d = fp12_mul(t0c, t2c);

    let t2e = cyclotomic_n_sqr(t2d, 6);
    let t2f = fp12_mul(t0c, t2e);

    let t2g = cyclotomic_n_sqr(t2f, 10);
    let t1c = fp12_mul(t1b, t2g);

    let t1d = cyclotomic_n_sqr(t1c, 6);
    let t0d = fp12_mul(t0c, t1d);
    return fp12_mul(result_a, t0d);
}

// =============================================================================
// G2 affine + projective ops + line evaluations.
// =============================================================================

struct G2A { x: F2, y: F2, inf: u32 };
struct G2P { x: F2, y: F2, z: F2 };

fn g2_neg(a: G2A) -> G2A {
    var r: G2A; r.x = a.x; r.y = fp2_neg_local(a.y); r.inf = a.inf; return r;
}
fn g2_to_proj(a: G2A) -> G2P {
    var p: G2P; p.x = a.x; p.y = a.y; p.z = fp2_one(); return p;
}

struct LineEval { r0: F2, r1: F2, r2: F2 };

// Doubling step: updates p in place via output, returns line eval (-H, 3 X^2, I).
fn g2_double_step(p_in: G2P) -> array<F2, 6> {
    // returns [px, py, pz, ev.r0, ev.r1, ev.r2]
    var A = fp2_mul(p_in.x, p_in.y);
    A = fp2_halve(A);
    let B = fp2_sqr(p_in.y);
    let C = fp2_sqr(p_in.z);
    var D = fp2_double(C);
    D = fp2_add(D, C);
    let E = mul_b_twist(D);
    var F = fp2_double(E);
    F = fp2_add(F, E);
    var G = fp2_add(B, F);
    G = fp2_halve(G);
    var H = fp2_add(p_in.y, p_in.z);
    H = fp2_sqr(H);
    let t1 = fp2_add(B, C);
    H = fp2_sub(H, t1);
    let I = fp2_sub(E, B);
    let J = fp2_sqr(p_in.x);
    let EE = fp2_sqr(E);
    var K = fp2_double(EE);
    K = fp2_add(K, EE);

    var px = fp2_sub(B, F);
    px = fp2_mul(px, A);
    var py = fp2_sqr(G);
    py = fp2_sub(py, K);
    let pz = fp2_mul(B, H);

    let r0 = fp2_neg_local(H);
    var r1 = fp2_double(J);
    r1 = fp2_add(r1, J);
    let r2 = I;

    return array<F2, 6>(px, py, pz, r0, r1, r2);
}

// Mixed-add step: adds affine `a` into projective `p`. Returns updated p + ev.
fn g2_add_mixed_step(p_in: G2P, a: G2A) -> array<F2, 6> {
    let Y2Z1 = fp2_mul(a.y, p_in.z);
    let O = fp2_sub(p_in.y, Y2Z1);
    let X2Z1 = fp2_mul(a.x, p_in.z);
    let L = fp2_sub(p_in.x, X2Z1);
    let C = fp2_sqr(O);
    let D = fp2_sqr(L);
    let E = fp2_mul(L, D);
    let F = fp2_mul(p_in.z, C);
    let G = fp2_mul(p_in.x, D);
    let t0 = fp2_double(G);
    var H = fp2_add(E, F);
    H = fp2_sub(H, t0);
    let t1 = fp2_mul(p_in.y, E);

    var px = fp2_mul(L, H);
    var py = fp2_sub(G, H);
    py = fp2_mul(py, O);
    py = fp2_sub(py, t1);
    let pz = fp2_mul(E, p_in.z);

    let t2 = fp2_mul(L, a.y);
    var J = fp2_mul(a.x, O);
    J = fp2_sub(J, t2);

    let r0 = L;
    let r1 = fp2_neg_local(O);
    let r2 = J;

    return array<F2, 6>(px, py, pz, r0, r1, r2);
}

// Line-only compute (no point update) -- used for the second 6x+2 correction.
fn g2_line_compute(p_in: G2P, a: G2A) -> LineEval {
    let Y2Z1 = fp2_mul(a.y, p_in.z);
    let O = fp2_sub(p_in.y, Y2Z1);
    let X2Z1 = fp2_mul(a.x, p_in.z);
    let L = fp2_sub(p_in.x, X2Z1);
    let t2 = fp2_mul(L, a.y);
    var J = fp2_mul(a.x, O);
    J = fp2_sub(J, t2);

    var ev: LineEval;
    ev.r0 = L;
    ev.r1 = fp2_neg_local(O);
    ev.r2 = J;
    return ev;
}

// =============================================================================
// 6x+2 NAF loop counter (matches CPU bn254_pairing.cpp:kLoopCounter).
// =============================================================================

const K_LOOP_NAF : array<i32, 65> = array<i32, 65>(
    0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0,
    0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0, 0, 1, 1,
    1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1,
    1, 0, 0, -1, 0, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, 1,
    1
);

// =============================================================================
// G1 affine struct already declared above; need a small typed alias for pairing.
// Each pairing input is one G1 affine point + one G2 affine point.
// =============================================================================

// Single-pair Miller loop. Multi-pair is host-driven (tree-reduce of Fp12s,
// single final-exp at end). Algorithm-equivalent to CPU bn254_pairing.cpp.
fn miller_one(P: G1A, Q: G2A) -> F12 {
    if (P.inf != 0u || Q.inf != 0u) { return fp12_one(); }

    var qProj = g2_to_proj(Q);
    let qNeg  = g2_neg(Q);

    var result = fp12_one();
    var l1: LineEval;
    var l2: LineEval;

    // Skip i=64 (LoopCounter[64] == 0 and result still 1).
    let s_d = g2_double_step(qProj);
    qProj.x = s_d[0]; qProj.y = s_d[1]; qProj.z = s_d[2];
    l1.r0 = s_d[3]; l1.r1 = s_d[4]; l1.r2 = s_d[5];
    result.c0.b0 = fp2_mul_by_fp(l1.r0, P.y);
    result.c1.b0 = fp2_mul_by_fp(l1.r1, P.x);
    result.c1.b1 = l1.r2;

    // i=63 (LoopCounter[63] == -1).
    result = fp12_sqr(result);
    let s_l2 = g2_line_compute(qProj, qNeg);
    l2.r0 = fp2_mul_by_fp(s_l2.r0, P.y);
    l2.r1 = fp2_mul_by_fp(s_l2.r1, P.x);
    l2.r2 = s_l2.r2;
    let s_a = g2_add_mixed_step(qProj, Q);
    qProj.x = s_a[0]; qProj.y = s_a[1]; qProj.z = s_a[2];
    l1.r0 = fp2_mul_by_fp(s_a[3], P.y);
    l1.r1 = fp2_mul_by_fp(s_a[4], P.x);
    l1.r2 = s_a[5];
    var prod = fp12_mul_034_by_034(l1.r0, l1.r1, l1.r2, l2.r0, l2.r1, l2.r2);
    result = fp12_mul_by_01234(result, prod);

    // i=62 .. 0
    for (var i = 65i - 4i; i >= 0i; i = i - 1i) {
        result = fp12_sqr(result);
        let sd2 = g2_double_step(qProj);
        qProj.x = sd2[0]; qProj.y = sd2[1]; qProj.z = sd2[2];
        l1.r0 = fp2_mul_by_fp(sd2[3], P.y);
        l1.r1 = fp2_mul_by_fp(sd2[4], P.x);
        l1.r2 = sd2[5];

        let lc = K_LOOP_NAF[i];
        if (lc == 1) {
            let sa2 = g2_add_mixed_step(qProj, Q);
            qProj.x = sa2[0]; qProj.y = sa2[1]; qProj.z = sa2[2];
            l2.r0 = fp2_mul_by_fp(sa2[3], P.y);
            l2.r1 = fp2_mul_by_fp(sa2[4], P.x);
            l2.r2 = sa2[5];
            prod = fp12_mul_034_by_034(l1.r0, l1.r1, l1.r2, l2.r0, l2.r1, l2.r2);
            result = fp12_mul_by_01234(result, prod);
        } else if (lc == -1) {
            let sa2 = g2_add_mixed_step(qProj, qNeg);
            qProj.x = sa2[0]; qProj.y = sa2[1]; qProj.z = sa2[2];
            l2.r0 = fp2_mul_by_fp(sa2[3], P.y);
            l2.r1 = fp2_mul_by_fp(sa2[4], P.x);
            l2.r2 = sa2[5];
            prod = fp12_mul_034_by_034(l1.r0, l1.r1, l1.r2, l2.r0, l2.r1, l2.r2);
            result = fp12_mul_by_01234(result, prod);
        } else {
            result = fp12_mul_by_034(result, l1.r0, l1.r1, l1.r2);
        }
    }

    // Final 6x+2 + Frobenius corrections: Q1 = pi(Q), Q2 = -pi^2(Q).
    var Q1: G2A;
    var Q2: G2A;
    let q1x = fp2_conjugate(Q.x);
    let q1y = fp2_conjugate(Q.y);
    var nr_p2: F2; nr_p2.a0 = K_NR1P2_A0; nr_p2.a1 = K_NR1P2_A1;
    var nr_p3: F2; nr_p3.a0 = K_NR1P3_A0; nr_p3.a1 = K_NR1P3_A1;
    Q1.x = fp2_mul(q1x, nr_p2);
    Q1.y = fp2_mul(q1y, nr_p3);
    Q1.inf = 0u;

    var q2x: F2; q2x.a0 = fp_mul(Q.x.a0, K_NR2P2); q2x.a1 = fp_mul(Q.x.a1, K_NR2P2);
    var q2y: F2; q2y.a0 = fp_mul(Q.y.a0, K_NR2P3); q2y.a1 = fp_mul(Q.y.a1, K_NR2P3);
    Q2.x = q2x; Q2.y = fp2_neg_local(q2y); Q2.inf = 0u;

    let saQ1 = g2_add_mixed_step(qProj, Q1);
    qProj.x = saQ1[0]; qProj.y = saQ1[1]; qProj.z = saQ1[2];
    l2.r0 = fp2_mul_by_fp(saQ1[3], P.y);
    l2.r1 = fp2_mul_by_fp(saQ1[4], P.x);
    l2.r2 = saQ1[5];
    let lcQ2 = g2_line_compute(qProj, Q2);
    l1.r0 = fp2_mul_by_fp(lcQ2.r0, P.y);
    l1.r1 = fp2_mul_by_fp(lcQ2.r1, P.x);
    l1.r2 = lcQ2.r2;
    prod = fp12_mul_034_by_034(l1.r0, l1.r1, l1.r2, l2.r0, l2.r1, l2.r2);
    result = fp12_mul_by_01234(result, prod);

    return result;
}

// =============================================================================
// Final exponentiation -- Fuentes-Castaneda hard part (eprint 2015/192).
// =============================================================================

fn final_exp(z: F12) -> F12 {
    var result = z;
    var t0 = fp12_conjugate(result);
    result = fp12_inv(result);
    t0 = fp12_mul(t0, result);
    result = frobenius_sq(t0);
    result = fp12_mul(result, t0);

    if (fp12_is_one(result)) { return result; }

    var t_0 = expt(result);
    t_0 = fp12_conjugate(t_0);
    t_0 = cyclotomic_sqr(t_0);
    var t_1 = cyclotomic_sqr(t_0);
    t_1 = fp12_mul(t_0, t_1);
    var t_2 = expt(t_1);
    t_2 = fp12_conjugate(t_2);
    var t_3 = fp12_conjugate(t_1);
    t_1 = fp12_mul(t_2, t_3);
    t_3 = cyclotomic_sqr(t_2);
    var t_4 = expt(t_3);
    t_4 = fp12_mul(t_1, t_4);
    t_3 = fp12_mul(t_0, t_4);
    t_0 = fp12_mul(t_2, t_4);
    t_0 = fp12_mul(result, t_0);
    t_2 = frobenius(t_3);
    t_0 = fp12_mul(t_2, t_0);
    t_2 = frobenius_sq(t_4);
    t_0 = fp12_mul(t_2, t_0);
    t_2 = fp12_conjugate(result);
    t_2 = fp12_mul(t_2, t_3);
    t_2 = frobenius_cube(t_2);
    t_0 = fp12_mul(t_2, t_0);

    return t_0;
}

// =============================================================================
// I/O packing for G2 affine + Fp12 (mirror CUDA wire format).
//   G2 affine: 36 u32  = (x.a0 || x.a1 || y.a0 || y.a1 || inf || pad)
//   Fp12:      96 u32  = 6 x Fp2 (c0.b0..c1.b2)
// =============================================================================

fn load_g2_a(off: u32) -> G2A {
    var p: G2A;
    for (var i = 0u; i < 8u; i = i + 1u) { p.x.a0[i] = in_a[off +  0u + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { p.x.a1[i] = in_a[off +  8u + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { p.y.a0[i] = in_a[off + 16u + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { p.y.a1[i] = in_a[off + 24u + i]; }
    p.inf = in_a[off + 32u];
    return p;
}

fn load_g2_b(off: u32) -> G2A {
    var p: G2A;
    for (var i = 0u; i < 8u; i = i + 1u) { p.x.a0[i] = in_b[off +  0u + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { p.x.a1[i] = in_b[off +  8u + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { p.y.a0[i] = in_b[off + 16u + i]; }
    for (var i = 0u; i < 8u; i = i + 1u) { p.y.a1[i] = in_b[off + 24u + i]; }
    p.inf = in_b[off + 32u];
    return p;
}

// =============================================================================
// Kernels: k_miller_iter (cyclo-sqr^100 stress) + k_pairing (full e(P,Q)).
// =============================================================================

@compute @workgroup_size(8)
fn k_miller_iter(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    let off = i * 96u;
    var z = f12_load_a(off);
    for (var k = 0i; k < 100i; k = k + 1) { z = cyclotomic_sqr(z); }
    f12_store(off, z);
}

@compute @workgroup_size(4)
fn k_pairing(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    let p_off = i * 18u;       // G1 affine: 8 + 8 + 2 padding
    let q_off = i * 36u;       // G2 affine: 32 (Fp2 x, Fp2 y) + 4 (inf + 3 pad)
    let out_off = i * 96u;     // Fp12: 96 u32

    let P = load_aff_a(p_off);
    let Q = load_g2_b(q_off);
    let m = miller_one(P, Q);
    let r = final_exp(m);
    f12_store(out_off, r);
}

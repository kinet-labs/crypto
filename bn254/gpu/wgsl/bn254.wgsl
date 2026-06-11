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
//   * G1:   Bernstein-Lange efl/jacobian-0/{dbl-2009-l, add-2007-bl}
//   * G1 mul: constant-time Montgomery ladder over 256 bits (no early exit)
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

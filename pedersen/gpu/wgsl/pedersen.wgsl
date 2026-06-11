// First-party WGSL kernel for batched Pedersen vector commitments over BN254 G1.
// Mechanically ported from pedersen/gpu/metal/pedersen.metal -- byte-equal to
// the Metal kernel and the Go canonical at github.com/kinet-labs/crypto/pedersen.
//
// 256-bit limbs are 8 x u32 little-endian (no native u64 in WGSL).
//
// Two-stage pipeline (driver dispatches twice with different entry points):
//   1. pedersen_pointmul    M*(N+1) threads, one per (commitment, term)
//   2. pedersen_reduce_add  M       threads, one per commitment
//
// Wire format (raw big-endian, gnark-crypto compatible):
//   gens_be     : (N + 1) * 64 bytes -- G_basis[0..N-1] || H, X then Y
//   scalars_be  : M * N * 32  bytes -- raw BE Fr elements
//   blindings_be: M * 32      bytes -- raw BE Fr elements
//   scratch     : M * (N+1) * 24 u32 -- (X || Y || Z) Montgomery, 8 limbs each
//   out_be      : M * 64      bytes -- (X || Y) raw BE
//
// Stage 1 binds: gens_be(0), scalars_be(1), blindings_be(2), scratch(3), dims(4)
// Stage 2 binds: scratch(0), out_be(1), dims(2)

// Bindings: stage 1
@group(0) @binding(0) var<storage, read>       gens_be       : array<u32>;
@group(0) @binding(1) var<storage, read>       scalars_be    : array<u32>;
@group(0) @binding(2) var<storage, read>       blindings_be  : array<u32>;
@group(0) @binding(3) var<storage, read_write> scratch       : array<u32>;
@group(0) @binding(4) var<uniform>             dims          : Dims;

// Bindings: stage 2 -- separate kernel must use distinct group(1) bindings to
// avoid being merged with stage 1 by the WGSL static binding analyzer.
@group(1) @binding(0) var<storage, read>       scratch_in    : array<u32>;
@group(1) @binding(1) var<storage, read_write> out_be        : array<u32>;
@group(1) @binding(2) var<uniform>             dims2         : Dims;

struct Dims {
    M: u32,
    N: u32,
    _pad0: u32,
    _pad1: u32,
}

// =============================================================================
// BN254 base-field constants -- 8 x u32 little-endian
// =============================================================================
// p = 0x30644E72E131A029 B85045B68181585D 97816A916871CA8D 3C208C16D87CFD47
const BN254_P = array<u32, 8>(
    0xD87CFD47u, 0x3C208C16u, 0x6871CA8Du, 0x97816A91u,
    0x8181585Du, 0xB85045B6u, 0xE131A029u, 0x30644E72u
);
// R = 2^256 mod p
const BN254_R_MONT = array<u32, 8>(
    0xC58F0D9Du, 0xD35D438Du, 0xF5C70B3Du, 0x0A78EB28u,
    0x7879462Cu, 0x666EA36Fu, 0x9A07DF2Fu, 0x0E0A77C1u
);
// R^2 mod p
const BN254_R2 = array<u32, 8>(
    0x538AFA89u, 0xF32CFC5Bu, 0xD44501FBu, 0xB5E71911u,
    0x0A417FF6u, 0x47AB1EFFu, 0xCAB8351Fu, 0x06D89F71u
);
// -p^{-1} mod 2^32 (low 32 bits of -p^{-1} mod 2^64 = 0x87D20782_E4866389)
const BN254_INV: u32 = 0xE4866389u;

// =============================================================================
// 256-bit (8 x u32) helpers
// =============================================================================

fn u256_zero() -> array<u32, 8> {
    return array<u32, 8>(0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u);
}

fn u256_is_zero(a: ptr<function, array<u32, 8>>) -> bool {
    var acc = 0u;
    for (var i = 0u; i < 8u; i = i + 1u) { acc = acc | (*a)[i]; }
    return acc == 0u;
}

fn u256_cmp(a: ptr<function, array<u32, 8>>, b: ptr<function, array<u32, 8>>) -> i32 {
    for (var i = 7i; i >= 0; i = i - 1) {
        let ui = u32(i);
        if ((*a)[ui] > (*b)[ui]) { return 1; }
        if ((*a)[ui] < (*b)[ui]) { return -1; }
    }
    return 0;
}

fn u256_add(a: ptr<function, array<u32, 8>>, b: ptr<function, array<u32, 8>>,
            r: ptr<function, array<u32, 8>>) -> u32 {
    var c = 0u;
    for (var i = 0u; i < 8u; i = i + 1u) {
        let s1 = (*a)[i] + c;
        c = select(0u, 1u, s1 < (*a)[i]);
        let s2 = s1 + (*b)[i];
        c = c + select(0u, 1u, s2 < s1);
        (*r)[i] = s2;
    }
    return c;
}

fn u256_sub(a: ptr<function, array<u32, 8>>, b: ptr<function, array<u32, 8>>,
            r: ptr<function, array<u32, 8>>) -> u32 {
    var bw = 0u;
    for (var i = 0u; i < 8u; i = i + 1u) {
        let d1 = (*a)[i] - bw;
        bw = select(0u, 1u, d1 > (*a)[i]);
        let d2 = d1 - (*b)[i];
        bw = bw + select(0u, 1u, d2 > d1);
        (*r)[i] = d2;
    }
    return bw;
}

// =============================================================================
// Montgomery reduction (CIOS) over BN254 p, 8x u32 limbs
// =============================================================================
//
// Mirrors mont_reduce in secp256k1.wgsl.  Given t in [0, p*R), returns t*R^{-1} mod p.

fn mont_reduce(t: ptr<function, array<u32, 16>>, r: ptr<function, array<u32, 8>>) {
    var p = BN254_P;
    var a: array<u32, 17>;
    for (var i = 0u; i < 16u; i = i + 1u) { a[i] = (*t)[i]; }
    a[16] = 0u;

    for (var i = 0u; i < 8u; i = i + 1u) {
        let u = a[i] * BN254_INV;
        var carry = 0u;
        for (var j = 0u; j < 8u; j = j + 1u) {
            // u * p[j] -> (hi, lo)
            let u_lo = u & 0xFFFFu; let u_hi = u >> 16u;
            let m_lo = p[j] & 0xFFFFu; let m_hi = p[j] >> 16u;
            let ll = u_lo * m_lo;
            let lh = u_lo * m_hi;
            let hl = u_hi * m_lo;
            let hh = u_hi * m_hi;
            let mid = lh + hl;
            var lo = ll + (mid << 16u);
            var hi = hh + (mid >> 16u) + select(0u, 1u, lo < ll) + select(0u, 0x10000u, mid < lh);

            let s1 = lo + carry;
            hi = hi + select(0u, 1u, s1 < lo);
            let s2 = a[i + j] + s1;
            hi = hi + select(0u, 1u, s2 < a[i + j]);
            a[i + j] = s2;
            carry = hi;
        }
        // propagate carry through high half
        for (var j = 8u; i + j <= 16u; j = j + 1u) {
            let s = a[i + j] + carry;
            carry = select(0u, 1u, s < a[i + j]);
            a[i + j] = s;
            if (carry == 0u) { break; }
        }
    }

    for (var i = 0u; i < 8u; i = i + 1u) { (*r)[i] = a[i + 8u]; }
    if (a[16] != 0u || u256_cmp(r, &p) >= 0) {
        _ = u256_sub(r, &p, r);
    }
}

fn mont_mul(a: ptr<function, array<u32, 8>>, b: ptr<function, array<u32, 8>>,
            r: ptr<function, array<u32, 8>>) {
    var t: array<u32, 16>;
    for (var i = 0u; i < 16u; i = i + 1u) { t[i] = 0u; }

    for (var i = 0u; i < 8u; i = i + 1u) {
        var carry = 0u;
        for (var j = 0u; j < 8u; j = j + 1u) {
            let al = (*a)[i] & 0xFFFFu; let ah = (*a)[i] >> 16u;
            let bl = (*b)[j] & 0xFFFFu; let bh = (*b)[j] >> 16u;
            let ll = al * bl;
            let lh = al * bh;
            let hl = ah * bl;
            let hh = ah * bh;
            let mid = lh + hl;
            var lo = ll + (mid << 16u);
            var hi = hh + (mid >> 16u) + select(0u, 1u, lo < ll) + select(0u, 0x10000u, mid < lh);
            let s1 = lo + carry; hi = hi + select(0u, 1u, s1 < lo);
            let s2 = t[i + j] + s1; hi = hi + select(0u, 1u, s2 < t[i + j]);
            t[i + j] = s2;
            carry = hi;
        }
        for (var j = 8u; i + j < 16u; j = j + 1u) {
            let s = t[i + j] + carry;
            carry = select(0u, 1u, s < t[i + j]);
            t[i + j] = s;
            if (carry == 0u) { break; }
        }
    }
    mont_reduce(&t, r);
}

// =============================================================================
// Field ops over p (Montgomery)
// =============================================================================

fn fp_add(a: ptr<function, array<u32, 8>>, b: ptr<function, array<u32, 8>>,
          r: ptr<function, array<u32, 8>>) {
    var p = BN254_P;
    let c = u256_add(a, b, r);
    if (c != 0u || u256_cmp(r, &p) >= 0) {
        _ = u256_sub(r, &p, r);
    }
}

fn fp_sub(a: ptr<function, array<u32, 8>>, b: ptr<function, array<u32, 8>>,
          r: ptr<function, array<u32, 8>>) {
    var p = BN254_P;
    let bw = u256_sub(a, b, r);
    if (bw != 0u) {
        _ = u256_add(r, &p, r);
    }
}

fn fp_mul(a: ptr<function, array<u32, 8>>, b: ptr<function, array<u32, 8>>,
          r: ptr<function, array<u32, 8>>) { mont_mul(a, b, r); }

fn fp_sqr(a: ptr<function, array<u32, 8>>, r: ptr<function, array<u32, 8>>) {
    mont_mul(a, a, r);
}

fn to_mont_p(a: ptr<function, array<u32, 8>>, r: ptr<function, array<u32, 8>>) {
    var r2 = BN254_R2;
    fp_mul(a, &r2, r);
}

fn from_mont_p(a: ptr<function, array<u32, 8>>, r: ptr<function, array<u32, 8>>) {
    var t: array<u32, 16>;
    for (var i = 0u; i < 16u; i = i + 1u) { t[i] = 0u; }
    for (var i = 0u; i < 8u; i = i + 1u) { t[i] = (*a)[i]; }
    mont_reduce(&t, r);
}

// Inversion via Fermat: a^(p-2)
fn fp_inv(a: ptr<function, array<u32, 8>>, r: ptr<function, array<u32, 8>>) {
    // p - 2 LE limbs
    var exp = array<u32, 8>(
        0xD87CFD45u, 0x3C208C16u, 0x6871CA8Du, 0x97816A91u,
        0x8181585Du, 0xB85045B6u, 0xE131A029u, 0x30644E72u
    );
    var one = array<u32, 8>(1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u);
    var result: array<u32, 8>;
    to_mont_p(&one, &result);
    var base: array<u32, 8>;
    for (var i = 0u; i < 8u; i = i + 1u) { base[i] = (*a)[i]; }

    for (var i = 0u; i < 8u; i = i + 1u) {
        for (var bit = 0u; bit < 32u; bit = bit + 1u) {
            if (((exp[i] >> bit) & 1u) != 0u) {
                var tmp: array<u32, 8>;
                fp_mul(&result, &base, &tmp);
                result = tmp;
            }
            var tmp2: array<u32, 8>;
            fp_sqr(&base, &tmp2);
            base = tmp2;
        }
    }
    *r = result;
}

// =============================================================================
// G1 in Jacobian (Montgomery X, Y, Z); Z == 0 represents infinity
// =============================================================================

struct G1Jac {
    x: array<u32, 8>,
    y: array<u32, 8>,
    z: array<u32, 8>,
}

fn g1_zero() -> G1Jac {
    var p: G1Jac;
    var one = array<u32, 8>(1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u);
    to_mont_p(&one, &p.x);
    p.y = p.x;
    p.z = u256_zero();
    return p;
}

fn g1_is_zero(p: ptr<function, G1Jac>) -> bool {
    var z = (*p).z;
    return u256_is_zero(&z);
}

// BN254 a = 0 doubling (matches Metal's fp formulas exactly)
fn g1_dbl(p: ptr<function, G1Jac>, r: ptr<function, G1Jac>) {
    if (g1_is_zero(p)) { *r = *p; return; }
    var A: array<u32, 8>; fp_sqr(&(*p).x, &A);
    var B: array<u32, 8>; fp_sqr(&(*p).y, &B);
    var C: array<u32, 8>; fp_sqr(&B, &C);
    var t: array<u32, 8>; fp_add(&(*p).x, &B, &t);
    var t2: array<u32, 8>; fp_sqr(&t, &t2);
    var t3: array<u32, 8>; fp_sub(&t2, &A, &t3);
    var t4: array<u32, 8>; fp_sub(&t3, &C, &t4);
    var D: array<u32, 8>; fp_add(&t4, &t4, &D);
    var twoA: array<u32, 8>; fp_add(&A, &A, &twoA);
    var E: array<u32, 8>;    fp_add(&twoA, &A, &E);
    var F: array<u32, 8>; fp_sqr(&E, &F);
    var twoD: array<u32, 8>; fp_add(&D, &D, &twoD);
    fp_sub(&F, &twoD, &(*r).x);
    var DminusX: array<u32, 8>; fp_sub(&D, &(*r).x, &DminusX);
    var EDX: array<u32, 8>; fp_mul(&E, &DminusX, &EDX);
    var twoC: array<u32, 8>; fp_add(&C, &C, &twoC);
    var fourC: array<u32, 8>; fp_add(&twoC, &twoC, &fourC);
    var eightC: array<u32, 8>; fp_add(&fourC, &fourC, &eightC);
    fp_sub(&EDX, &eightC, &(*r).y);
    var YZ: array<u32, 8>; fp_mul(&(*p).y, &(*p).z, &YZ);
    fp_add(&YZ, &YZ, &(*r).z);
}

// Mixed Jacobian + Affine addition, byte-identical to Metal g1_add_mixed
fn g1_add_mixed(p: ptr<function, G1Jac>, qx: ptr<function, array<u32, 8>>,
                qy: ptr<function, array<u32, 8>>, r: ptr<function, G1Jac>) {
    if (g1_is_zero(p)) {
        (*r).x = *qx; (*r).y = *qy;
        var one = array<u32, 8>(1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u);
        to_mont_p(&one, &(*r).z);
        return;
    }
    var Z1Z1: array<u32, 8>; fp_sqr(&(*p).z, &Z1Z1);
    var U2: array<u32, 8>; fp_mul(qx, &Z1Z1, &U2);
    var ZZ1Z1: array<u32, 8>; fp_mul(&(*p).z, &Z1Z1, &ZZ1Z1);
    var S2: array<u32, 8>; fp_mul(qy, &ZZ1Z1, &S2);
    var H: array<u32, 8>; fp_sub(&U2, &(*p).x, &H);
    var R: array<u32, 8>; fp_sub(&S2, &(*p).y, &R);

    if (u256_is_zero(&H)) {
        if (u256_is_zero(&R)) { g1_dbl(p, r); return; }
        *r = g1_zero();
        return;
    }
    var HH: array<u32, 8>; fp_sqr(&H, &HH);
    var twoHH: array<u32, 8>; fp_add(&HH, &HH, &twoHH);
    var I: array<u32, 8>; fp_add(&twoHH, &twoHH, &I);
    var J: array<u32, 8>; fp_mul(&H, &I, &J);
    var R2: array<u32, 8>; fp_add(&R, &R, &R2);
    var V: array<u32, 8>; fp_mul(&(*p).x, &I, &V);

    var Rsq: array<u32, 8>; fp_sqr(&R2, &Rsq);
    var t1: array<u32, 8>; fp_sub(&Rsq, &J, &t1);
    var twoV: array<u32, 8>; fp_add(&V, &V, &twoV);
    fp_sub(&t1, &twoV, &(*r).x);
    var VminusX3: array<u32, 8>; fp_sub(&V, &(*r).x, &VminusX3);
    var RVX: array<u32, 8>; fp_mul(&R2, &VminusX3, &RVX);
    var Y1J: array<u32, 8>; fp_mul(&(*p).y, &J, &Y1J);
    var twoY1J: array<u32, 8>; fp_add(&Y1J, &Y1J, &twoY1J);
    fp_sub(&RVX, &twoY1J, &(*r).y);
    var twoH: array<u32, 8>; fp_add(&H, &H, &twoH);
    fp_mul(&(*p).z, &twoH, &(*r).z);
}

// Full Jacobian addition (matches Metal g1_add)
fn g1_add(p: ptr<function, G1Jac>, q: ptr<function, G1Jac>, r: ptr<function, G1Jac>) {
    if (g1_is_zero(p)) { *r = *q; return; }
    if (g1_is_zero(q)) { *r = *p; return; }
    var Z1Z1: array<u32, 8>; fp_sqr(&(*p).z, &Z1Z1);
    var Z2Z2: array<u32, 8>; fp_sqr(&(*q).z, &Z2Z2);
    var U1: array<u32, 8>; fp_mul(&(*p).x, &Z2Z2, &U1);
    var U2: array<u32, 8>; fp_mul(&(*q).x, &Z1Z1, &U2);
    var Yq: array<u32, 8>; fp_mul(&(*p).y, &(*q).z, &Yq);
    var S1: array<u32, 8>; fp_mul(&Yq, &Z2Z2, &S1);
    var Yp: array<u32, 8>; fp_mul(&(*q).y, &(*p).z, &Yp);
    var S2: array<u32, 8>; fp_mul(&Yp, &Z1Z1, &S2);
    var H: array<u32, 8>; fp_sub(&U2, &U1, &H);
    var R: array<u32, 8>; fp_sub(&S2, &S1, &R);
    if (u256_is_zero(&H)) {
        if (u256_is_zero(&R)) { g1_dbl(p, r); return; }
        *r = g1_zero();
        return;
    }
    var R2: array<u32, 8>; fp_add(&R, &R, &R2);
    var HH: array<u32, 8>; fp_sqr(&H, &HH);
    var twoHH: array<u32, 8>; fp_add(&HH, &HH, &twoHH);
    var I: array<u32, 8>; fp_add(&twoHH, &twoHH, &I);
    var J: array<u32, 8>; fp_mul(&H, &I, &J);
    var V: array<u32, 8>; fp_mul(&U1, &I, &V);
    var Rsq: array<u32, 8>; fp_sqr(&R2, &Rsq);
    var t1: array<u32, 8>; fp_sub(&Rsq, &J, &t1);
    var twoV: array<u32, 8>; fp_add(&V, &V, &twoV);
    fp_sub(&t1, &twoV, &(*r).x);
    var VmX: array<u32, 8>; fp_sub(&V, &(*r).x, &VmX);
    var RVX: array<u32, 8>; fp_mul(&R2, &VmX, &RVX);
    var S1J: array<u32, 8>; fp_mul(&S1, &J, &S1J);
    var twoS1J: array<u32, 8>; fp_add(&S1J, &S1J, &twoS1J);
    fp_sub(&RVX, &twoS1J, &(*r).y);
    var Z1Z2: array<u32, 8>; fp_mul(&(*p).z, &(*q).z, &Z1Z2);
    var twoH: array<u32, 8>; fp_add(&H, &H, &twoH);
    fp_mul(&Z1Z2, &twoH, &(*r).z);
}

fn g1_to_affine(p: ptr<function, G1Jac>, ax: ptr<function, array<u32, 8>>,
                ay: ptr<function, array<u32, 8>>) -> bool {
    if (g1_is_zero(p)) { *ax = u256_zero(); *ay = u256_zero(); return true; }
    var Zinv: array<u32, 8>; fp_inv(&(*p).z, &Zinv);
    var Zinv2: array<u32, 8>; fp_sqr(&Zinv, &Zinv2);
    var Zinv3: array<u32, 8>; fp_mul(&Zinv2, &Zinv, &Zinv3);
    fp_mul(&(*p).x, &Zinv2, ax);
    fp_mul(&(*p).y, &Zinv3, ay);
    return false;
}

fn g1_scalar_mul_aff(qx: ptr<function, array<u32, 8>>, qy: ptr<function, array<u32, 8>>,
                     s:  ptr<function, array<u32, 8>>) -> G1Jac {
    var acc = g1_zero();
    // top word first (MSB) -- 8 u32 limbs LE means limb[7] is most significant
    for (var li = 7i; li >= 0; li = li - 1) {
        let limb = (*s)[u32(li)];
        for (var bi = 31i; bi >= 0; bi = bi - 1) {
            var dbl: G1Jac;
            g1_dbl(&acc, &dbl);
            acc = dbl;
            if (((limb >> u32(bi)) & 1u) != 0u) {
                var tmp: G1Jac;
                g1_add_mixed(&acc, qx, qy, &tmp);
                acc = tmp;
            }
        }
    }
    return acc;
}

// =============================================================================
// I/O: 32-byte BE field element (8 BE u32 words) <-> 8 LE u32 limbs
// =============================================================================
//
// The host uploads raw BE bytes. WGSL reads u32 from the storage buffer as the
// host's native u32 (little-endian on every consumer GPU). So a 32-byte BE
// field element, viewed as 8 host u32s, is a sequence of byte-swapped limbs in
// reverse order: word[0] = bytes 0..3 (most significant 4 BE bytes), and the
// LE limb[7] equals byteswap(word[0]).

fn bswap32(x: u32) -> u32 {
    return ((x & 0x000000FFu) << 24u)
         | ((x & 0x0000FF00u) <<  8u)
         | ((x & 0x00FF0000u) >>  8u)
         | ((x & 0xFF000000u) >> 24u);
}

fn read_be32_gens(word_off: u32) -> array<u32, 8> {
    var r: array<u32, 8>;
    for (var i = 0u; i < 8u; i = i + 1u) {
        r[i] = bswap32(gens_be[word_off + 7u - i]);
    }
    return r;
}

fn read_be32_scalars(word_off: u32) -> array<u32, 8> {
    var r: array<u32, 8>;
    for (var i = 0u; i < 8u; i = i + 1u) {
        r[i] = bswap32(scalars_be[word_off + 7u - i]);
    }
    return r;
}

fn read_be32_blindings(word_off: u32) -> array<u32, 8> {
    var r: array<u32, 8>;
    for (var i = 0u; i < 8u; i = i + 1u) {
        r[i] = bswap32(blindings_be[word_off + 7u - i]);
    }
    return r;
}

fn write_be32_out(word_off: u32, a: ptr<function, array<u32, 8>>) {
    for (var i = 0u; i < 8u; i = i + 1u) {
        out_be[word_off + i] = bswap32((*a)[7u - i]);
    }
}

// =============================================================================
// Stage 1 kernel: pedersen_pointmul
// =============================================================================
// One thread per (m, i):  scratch[m*(N+1)+i] = scalar_{m,i} * P_i
// where P_i = G_basis[i] for i<N, else H; scalar = S[m][i] for i<N, else r[m].
//
// Scratch layout: 24 u32 per slot = X(8) || Y(8) || Z(8), Montgomery form.

@compute @workgroup_size(64)
fn pedersen_pointmul(@builtin(global_invocation_id) gid: vec3<u32>) {
    let tid = gid.x;
    let M = dims.M;
    let N = dims.N;
    let total = M * (N + 1u);
    if (tid >= total) { return; }

    let m = tid / (N + 1u);
    let i = tid - m * (N + 1u);

    // Pick generator (32 BE bytes = 8 host u32 each for X, Y).
    var Qx_raw: array<u32, 8>;
    var Qy_raw: array<u32, 8>;
    var scalar_raw: array<u32, 8>;
    if (i < N) {
        Qx_raw = read_be32_gens(i * 16u);
        Qy_raw = read_be32_gens(i * 16u + 8u);
        scalar_raw = read_be32_scalars((m * N + i) * 8u);
    } else {
        Qx_raw = read_be32_gens(N * 16u);
        Qy_raw = read_be32_gens(N * 16u + 8u);
        scalar_raw = read_be32_blindings(m * 8u);
    }

    // To Montgomery form for X, Y; scalar stays as raw integer (limbs).
    var Qx_mont: array<u32, 8>; to_mont_p(&Qx_raw, &Qx_mont);
    var Qy_mont: array<u32, 8>; to_mont_p(&Qy_raw, &Qy_mont);

    let result = g1_scalar_mul_aff(&Qx_mont, &Qy_mont, &scalar_raw);

    let base = tid * 24u;
    for (var k = 0u; k < 8u; k = k + 1u) { scratch[base +  0u + k] = result.x[k]; }
    for (var k = 0u; k < 8u; k = k + 1u) { scratch[base +  8u + k] = result.y[k]; }
    for (var k = 0u; k < 8u; k = k + 1u) { scratch[base + 16u + k] = result.z[k]; }
}

// =============================================================================
// Stage 2 kernel: pedersen_reduce_add
// =============================================================================
// One thread per commitment; sums (N+1) Jacobian terms, converts to affine,
// emits 64 BE bytes as (X || Y).

fn scratch_load(idx: u32) -> G1Jac {
    var r: G1Jac;
    let base = idx * 24u;
    for (var k = 0u; k < 8u; k = k + 1u) { r.x[k] = scratch_in[base +  0u + k]; }
    for (var k = 0u; k < 8u; k = k + 1u) { r.y[k] = scratch_in[base +  8u + k]; }
    for (var k = 0u; k < 8u; k = k + 1u) { r.z[k] = scratch_in[base + 16u + k]; }
    return r;
}

@compute @workgroup_size(32)
fn pedersen_reduce_add(@builtin(global_invocation_id) gid: vec3<u32>) {
    let m = gid.x;
    let M = dims2.M;
    let N = dims2.N;
    if (m >= M) { return; }

    let base = m * (N + 1u);
    var acc = g1_zero();
    for (var i = 0u; i < N + 1u; i = i + 1u) {
        var term = scratch_load(base + i);
        if (g1_is_zero(&term)) { continue; }
        var sum: G1Jac;
        g1_add(&acc, &term, &sum);
        acc = sum;
    }

    var aff_x: array<u32, 8>; var aff_y: array<u32, 8>;
    let inf = g1_to_affine(&acc, &aff_x, &aff_y);
    let out_word = m * 16u;  // 64 bytes / 4 = 16 u32 words per commitment
    if (inf) {
        for (var k = 0u; k < 16u; k = k + 1u) { out_be[out_word + k] = 0u; }
        return;
    }
    var X_raw: array<u32, 8>; from_mont_p(&aff_x, &X_raw);
    var Y_raw: array<u32, 8>; from_mont_p(&aff_y, &Y_raw);
    write_be32_out(out_word,        &X_raw);
    write_be32_out(out_word + 8u,   &Y_raw);
}

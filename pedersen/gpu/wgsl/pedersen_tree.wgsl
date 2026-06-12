// Tree-reduce WGSL kernel for batched Pedersen vector commitments at the
// fixed Verkle width N = 256. One workgroup per commitment, 256 invocations
// per workgroup. Workgroup-local var<workgroup> array holds the 256 partial
// points; an 8-stride workgroupBarrier-synchronised reduction collapses
// them inside the same dispatch.
//
// 256-bit limbs are 8 x u32 little-endian (no native u64 in WGSL).
//
// Bindings:
//   group(0) binding(0) gens_be       : storage<read>
//   group(0) binding(1) scalars_be    : storage<read>
//   group(0) binding(2) blindings_be  : storage<read>
//   group(0) binding(3) out_be        : storage<read_write>
//   group(0) binding(4) dims          : uniform
//
// Output byte-equal to pedersen_tree_metal / pedersen_tree_cuda and the legacy
// two-stage pedersen.wgsl pipeline.

@group(0) @binding(0) var<storage, read>       gens_be       : array<u32>;
@group(0) @binding(1) var<storage, read>       scalars_be    : array<u32>;
@group(0) @binding(2) var<storage, read>       blindings_be  : array<u32>;
@group(0) @binding(3) var<storage, read_write> out_be        : array<u32>;
@group(0) @binding(4) var<uniform>             dims          : Dims;

struct Dims {
    M: u32,
    N: u32,
    _pad0: u32,
    _pad1: u32,
}

// =============================================================================
// BN254 base-field constants -- 8 x u32 LE
// =============================================================================
// p = 0x30644E72E131A029 B85045B68181585D 97816A916871CA8D 3C208C16D87CFD47
const BN254_P = array<u32, 8>(
    0xD87CFD47u, 0x3C208C16u, 0x6871CA8Du, 0x97816A91u,
    0x8181585Du, 0xB85045B6u, 0xE131A029u, 0x30644E72u
);
const BN254_R_MONT = array<u32, 8>(
    0xC58F0D9Du, 0xD35D438Du, 0xF5C70B3Du, 0x0A78EB28u,
    0x7879462Cu, 0x666EA36Fu, 0x9A07DF2Fu, 0x0E0A77C1u
);
const BN254_R2 = array<u32, 8>(
    0x538AFA89u, 0xF32CFC5Bu, 0xD44501FBu, 0xB5E71911u,
    0x0A417FF6u, 0x47AB1EFFu, 0xCAB8351Fu, 0x06D89F71u
);
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

fn mont_reduce(t: ptr<function, array<u32, 16>>, r: ptr<function, array<u32, 8>>) {
    var p = BN254_P;
    var a: array<u32, 17>;
    for (var i = 0u; i < 16u; i = i + 1u) { a[i] = (*t)[i]; }
    a[16] = 0u;

    for (var i = 0u; i < 8u; i = i + 1u) {
        let u = a[i] * BN254_INV;
        var carry = 0u;
        for (var j = 0u; j < 8u; j = j + 1u) {
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

fn fp_inv(a: ptr<function, array<u32, 8>>, r: ptr<function, array<u32, 8>>) {
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
// I/O helpers (raw 32-byte BE field element <-> 8 LE u32 limbs)
// =============================================================================

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
// Workgroup-shared tree reduction storage
// =============================================================================
// 256 slots * 24 u32 (X || Y || Z) = 24 KiB per workgroup. Within the
// minimum required workgroup-storage budget on every WebGPU adapter
// (16 KiB minimum per WebGPU spec, 32 KiB on every modern GPU we target).
//
// NOTE: WebGPU requires workgroup storage <= the device's
// maxComputeWorkgroupStorageSize. Dawn / wgpu-native both expose
// >= 16384 bytes by spec; in practice 32+ KiB on the GPUs we run.
// 256 * 24 * 4 = 24576 bytes. At spec floor (16384) this kernel cannot
// run; that is documented as the trade-off for a single-dispatch design.

const PED_TREE_N : u32 = 256u;

var<workgroup> shared_pts : array<array<u32, 24>, PED_TREE_N>;

@compute @workgroup_size(256)
fn pedersen_tree_commit(
    @builtin(workgroup_id)              wgid : vec3<u32>,
    @builtin(local_invocation_id)        lid : vec3<u32>,
) {
    let M = dims.M;
    let N = dims.N;
    let bid = wgid.x;
    let tid = lid.x;
    if (bid >= M) { return; }
    if (tid >= N) { return; }

    // Phase 1: each thread computes its term P[i] = scalars[bid,tid] * G[tid].
    var Qx_raw = read_be32_gens(tid * 16u);
    var Qy_raw = read_be32_gens(tid * 16u + 8u);
    var sc_raw = read_be32_scalars((bid * N + tid) * 8u);
    var Qx_mont: array<u32, 8>; to_mont_p(&Qx_raw, &Qx_mont);
    var Qy_mont: array<u32, 8>; to_mont_p(&Qy_raw, &Qy_mont);
    let P = g1_scalar_mul_aff(&Qx_mont, &Qy_mont, &sc_raw);

    // Stash in workgroup memory.
    for (var k = 0u; k < 8u; k = k + 1u) { shared_pts[tid][ 0u + k] = P.x[k]; }
    for (var k = 0u; k < 8u; k = k + 1u) { shared_pts[tid][ 8u + k] = P.y[k]; }
    for (var k = 0u; k < 8u; k = k + 1u) { shared_pts[tid][16u + k] = P.z[k]; }
    workgroupBarrier();

    // Phase 2: tree reduction (8 strides for N = 256).
    var stride : u32 = 128u;
    loop {
        if (stride == 0u) { break; }
        if (tid < stride) {
            var a: G1Jac;
            for (var k = 0u; k < 8u; k = k + 1u) { a.x[k] = shared_pts[tid][ 0u + k]; }
            for (var k = 0u; k < 8u; k = k + 1u) { a.y[k] = shared_pts[tid][ 8u + k]; }
            for (var k = 0u; k < 8u; k = k + 1u) { a.z[k] = shared_pts[tid][16u + k]; }
            var b: G1Jac;
            for (var k = 0u; k < 8u; k = k + 1u) { b.x[k] = shared_pts[tid + stride][ 0u + k]; }
            for (var k = 0u; k < 8u; k = k + 1u) { b.y[k] = shared_pts[tid + stride][ 8u + k]; }
            for (var k = 0u; k < 8u; k = k + 1u) { b.z[k] = shared_pts[tid + stride][16u + k]; }
            var sum: G1Jac;
            g1_add(&a, &b, &sum);
            for (var k = 0u; k < 8u; k = k + 1u) { shared_pts[tid][ 0u + k] = sum.x[k]; }
            for (var k = 0u; k < 8u; k = k + 1u) { shared_pts[tid][ 8u + k] = sum.y[k]; }
            for (var k = 0u; k < 8u; k = k + 1u) { shared_pts[tid][16u + k] = sum.z[k]; }
        }
        workgroupBarrier();
        stride = stride >> 1u;
    }

    // Phase 3 + 4: thread 0 finishes (load reduced sum, add r*H, emit).
    if (tid == 0u) {
        var acc: G1Jac;
        for (var k = 0u; k < 8u; k = k + 1u) { acc.x[k] = shared_pts[0u][ 0u + k]; }
        for (var k = 0u; k < 8u; k = k + 1u) { acc.y[k] = shared_pts[0u][ 8u + k]; }
        for (var k = 0u; k < 8u; k = k + 1u) { acc.z[k] = shared_pts[0u][16u + k]; }

        var Hx_raw = read_be32_gens(N * 16u);
        var Hy_raw = read_be32_gens(N * 16u + 8u);
        var r_raw  = read_be32_blindings(bid * 8u);
        var Hx_mont: array<u32, 8>; to_mont_p(&Hx_raw, &Hx_mont);
        var Hy_mont: array<u32, 8>; to_mont_p(&Hy_raw, &Hy_mont);
        var rH = g1_scalar_mul_aff(&Hx_mont, &Hy_mont, &r_raw);
        var sum: G1Jac;
        g1_add(&acc, &rH, &sum);
        acc = sum;

        var aff_x: array<u32, 8>; var aff_y: array<u32, 8>;
        let inf = g1_to_affine(&acc, &aff_x, &aff_y);
        let out_word = bid * 16u;
        if (inf) {
            for (var k = 0u; k < 16u; k = k + 1u) { out_be[out_word + k] = 0u; }
            return;
        }
        var X_raw: array<u32, 8>; from_mont_p(&aff_x, &X_raw);
        var Y_raw: array<u32, 8>; from_mont_p(&aff_y, &Y_raw);
        write_be32_out(out_word,        &X_raw);
        write_be32_out(out_word + 8u,   &Y_raw);
    }
}

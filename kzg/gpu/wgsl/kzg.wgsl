// WGSL kernel for KZG over BLS12-381 scalar field Fr (4 x u64 limbs,
// Montgomery form). Byte-equal mirror of the CPU oracle in
// kzg/cpp/kzg_oracle.hpp. Reuses the 6-limb Fp arithmetic conventions from
// bls/gpu/wgsl/bls_fp_ops.wgsl for any G1-based extension; this file
// implements the 4-limb Fr layer (BLS12-381 scalar field) the polynomial
// commitment requires.
//
// WGSL has no u64; all 64-bit ops are emulated as (lo: u32, hi: u32) pairs.
// Storage layout: each Fr value occupies 8 contiguous u32 little-endian
// words. CPU↔GPU agreement holds because canonical 32-byte-LE encoding is
// the on-the-wire form; the WGSL kernel reads BE bytes from the blob and
// writes LE Fr + 16-byte zero pad to the commit/proof buffer.

struct U64 { lo: u32, hi: u32 };

@group(0) @binding(0) var<storage, read>       input_a: array<u32>;
@group(0) @binding(1) var<storage, read>       input_b: array<u32>;
@group(0) @binding(2) var<storage, read_write> output:  array<u32>;
@group(0) @binding(3) var<uniform>             params:  vec4<u32>; // x = N

fn FR_R_MOD_lo(i: u32) -> u32 {
    if (i == 0u) { return 0x00000001u; }
    if (i == 1u) { return 0xFFFE5BFEu; }
    if (i == 2u) { return 0x09A1D805u; }
    if (i == 3u) { return 0x299D7D48u; }
    return 0u;
}
fn FR_R_MOD_hi(i: u32) -> u32 {
    if (i == 0u) { return 0xFFFFFFFFu; }
    if (i == 1u) { return 0x53BDA402u; }
    if (i == 2u) { return 0x3339D808u; }
    if (i == 3u) { return 0x73EDA753u; }
    return 0u;
}
fn FR_R2_lo(i: u32) -> u32 {
    if (i == 0u) { return 0xF3F29C6Du; }
    if (i == 1u) { return 0x87925C23u; }
    if (i == 2u) { return 0x7254398Fu; }
    if (i == 3u) { return 0x9F59FF11u; }
    return 0u;
}
fn FR_R2_hi(i: u32) -> u32 {
    if (i == 0u) { return 0xC999E990u; }
    if (i == 1u) { return 0x2B6CEDCBu; }
    if (i == 2u) { return 0x05D31496u; }
    if (i == 3u) { return 0x0748D9D9u; }
    return 0u;
}
fn FR_INV_lo() -> u32 { return 0xFFFFFFFFu; }
fn FR_INV_hi() -> u32 { return 0xFFFFFFFEu; }

fn u64_zero() -> U64 { return U64(0u, 0u); }

fn u64_add(a: U64, b: U64) -> U64 {
    let lo = a.lo + b.lo;
    let carry: u32 = select(0u, 1u, lo < a.lo);
    let hi = a.hi + b.hi + carry;
    return U64(lo, hi);
}

fn u64_sub_borrow(a: U64, b: U64) -> vec3<u32> {
    let lo = a.lo - b.lo;
    let bw1: u32 = select(0u, 1u, lo > a.lo);
    let hi_sub = a.hi - b.hi;
    let bw2: u32 = select(0u, 1u, hi_sub > a.hi);
    let hi = hi_sub - bw1;
    let bw3: u32 = select(0u, 1u, hi > hi_sub);
    return vec3<u32>(lo, hi, bw2 + bw3);
}

fn mul32(a: u32, b: u32) -> U64 {
    let al = a & 0xFFFFu;
    let ah = a >> 16u;
    let bl = b & 0xFFFFu;
    let bh = b >> 16u;
    let ll = al * bl;
    let lh = al * bh;
    let hl = ah * bl;
    let hh = ah * bh;
    let mid = lh + (ll >> 16u);
    let mid2 = mid + hl;
    var hi = hh + (mid2 >> 16u);
    if (mid2 < mid) { hi = hi + 0x10000u; }
    let lo = (mid2 << 16u) | (ll & 0xFFFFu);
    return U64(lo, hi);
}

struct U128 { lo: U64, hi: U64 };

fn u64_mul(a: U64, b: U64) -> U128 {
    let p_ll = mul32(a.lo, b.lo);
    let p_lh = mul32(a.lo, b.hi);
    let p_hl = mul32(a.hi, b.lo);
    let p_hh = mul32(a.hi, b.hi);
    var lo = U64(p_ll.lo, 0u);
    var carry: u32 = 0u;
    let s1 = p_ll.hi + p_lh.lo;
    if (s1 < p_ll.hi) { carry = carry + 1u; }
    let s2 = s1 + p_hl.lo;
    if (s2 < s1) { carry = carry + 1u; }
    lo.hi = s2;
    var hi_lo = p_hh.lo;
    var hi_hi = p_hh.hi;
    var c2: u32 = 0u;
    let h1 = hi_lo + p_lh.hi;
    if (h1 < hi_lo) { c2 = c2 + 1u; }
    let h2 = h1 + p_hl.hi;
    if (h2 < h1) { c2 = c2 + 1u; }
    let h3 = h2 + carry;
    if (h3 < h2) { c2 = c2 + 1u; }
    hi_lo = h3;
    hi_hi = hi_hi + c2;
    return U128(lo, U64(hi_lo, hi_hi));
}

fn fr_load_mod_i(i: u32) -> U64 { return U64(FR_R_MOD_lo(i), FR_R_MOD_hi(i)); }
fn fr_load_R2_i (i: u32) -> U64 { return U64(FR_R2_lo(i),    FR_R2_hi(i));    }

fn fr_geq_mod(a: array<U64, 4>) -> bool {
    let m3 = fr_load_mod_i(3u);
    if (a[3].hi != m3.hi) { return a[3].hi > m3.hi; }
    if (a[3].lo != m3.lo) { return a[3].lo > m3.lo; }
    let m2 = fr_load_mod_i(2u);
    if (a[2].hi != m2.hi) { return a[2].hi > m2.hi; }
    if (a[2].lo != m2.lo) { return a[2].lo > m2.lo; }
    let m1 = fr_load_mod_i(1u);
    if (a[1].hi != m1.hi) { return a[1].hi > m1.hi; }
    if (a[1].lo != m1.lo) { return a[1].lo > m1.lo; }
    let m0 = fr_load_mod_i(0u);
    if (a[0].hi != m0.hi) { return a[0].hi > m0.hi; }
    return a[0].lo >= m0.lo;
}

fn fr_sub_mod(a: array<U64, 4>) -> array<U64, 4> {
    var r: array<U64, 4>;
    var borrow: u32 = 0u;
    for (var i: u32 = 0u; i < 4u; i = i + 1u) {
        let bb = U64(borrow, 0u);
        let s1 = u64_sub_borrow(a[i], bb);
        let m  = fr_load_mod_i(i);
        let s2 = u64_sub_borrow(U64(s1.x, s1.y), m);
        r[i] = U64(s2.x, s2.y);
        borrow = s1.z + s2.z;
    }
    return r;
}

fn fr_add(a: array<U64, 4>, b: array<U64, 4>) -> array<U64, 4> {
    var r: array<U64, 4>;
    var carry: u32 = 0u;
    for (var i: u32 = 0u; i < 4u; i = i + 1u) {
        let s1 = u64_add(a[i], U64(carry, 0u));
        let cy1: u32 = select(0u, 1u, s1.lo < a[i].lo);
        let s2 = u64_add(s1, b[i]);
        let cy2: u32 = select(0u, 1u, s2.lo < s1.lo);
        r[i] = s2;
        carry = cy1 + cy2;
    }
    if (carry != 0u || fr_geq_mod(r)) {
        r = fr_sub_mod(r);
    }
    return r;
}

fn fr_mont_mul(a: array<U64, 4>, b: array<U64, 4>) -> array<U64, 4> {
    var t: array<U64, 5> = array<U64, 5>(u64_zero(), u64_zero(), u64_zero(),
                                          u64_zero(), u64_zero());
    let inv = U64(FR_INV_lo(), FR_INV_hi());
    for (var i: u32 = 0u; i < 4u; i = i + 1u) {
        var carry: U64 = u64_zero();
        for (var j: u32 = 0u; j < 4u; j = j + 1u) {
            let prod = u64_mul(a[i], b[j]);
            let s1 = u64_add(prod.lo, carry);
            let cy1: u32 = select(0u, 1u, s1.lo < prod.lo.lo);
            let s2 = u64_add(t[j], s1);
            let cy2: u32 = select(0u, 1u, s2.lo < t[j].lo);
            t[j] = s2;
            carry = u64_add(prod.hi, U64(cy1 + cy2, 0u));
        }
        t[4u] = u64_add(t[4u], carry);

        let u = u64_mul(t[0u], inv).lo;
        var k_carry: U64 = u64_zero();
        for (var j: u32 = 0u; j < 4u; j = j + 1u) {
            let m = fr_load_mod_i(j);
            let prod = u64_mul(u, m);
            let s1 = u64_add(prod.lo, k_carry);
            let cy1: u32 = select(0u, 1u, s1.lo < prod.lo.lo);
            let s2 = u64_add(t[j], s1);
            let cy2: u32 = select(0u, 1u, s2.lo < t[j].lo);
            t[j] = s2;
            k_carry = u64_add(prod.hi, U64(cy1 + cy2, 0u));
        }
        t[4u] = u64_add(t[4u], k_carry);
        for (var j: u32 = 0u; j < 4u; j = j + 1u) { t[j] = t[j + 1u]; }
        t[4u] = u64_zero();
    }
    var r = array<U64, 4>(t[0u], t[1u], t[2u], t[3u]);
    if (fr_geq_mod(r)) { r = fr_sub_mod(r); }
    return r;
}

fn fr_to_mont(a: array<U64, 4>) -> array<U64, 4> {
    let R2 = array<U64, 4>(fr_load_R2_i(0u), fr_load_R2_i(1u),
                           fr_load_R2_i(2u), fr_load_R2_i(3u));
    return fr_mont_mul(a, R2);
}
fn fr_from_mont(a: array<U64, 4>) -> array<U64, 4> {
    let ONE = array<U64, 4>(U64(1u, 0u), u64_zero(), u64_zero(), u64_zero());
    return fr_mont_mul(a, ONE);
}

fn bswap32(w: u32) -> u32 {
    return ((w & 0xFFu) << 24u) | (((w >> 8u) & 0xFFu) << 16u) |
           (((w >> 16u) & 0xFFu) << 8u) | ((w >> 24u) & 0xFFu);
}

fn fr_from_be_blob(blob_word_off: u32, fe_index: u32) -> array<U64, 4> {
    var limbs: array<U64, 4>;
    let base = blob_word_off + fe_index * 8u;
    for (var i: u32 = 0u; i < 4u; i = i + 1u) {
        let w0 = bswap32(input_a[base + (3u - i) * 2u]);
        let w1 = bswap32(input_a[base + (3u - i) * 2u + 1u]);
        limbs[i] = U64(w1, w0);
    }
    var done: bool = false;
    for (var k: u32 = 0u; k < 2u; k = k + 1u) {
        if (!done && fr_geq_mod(limbs)) {
            limbs = fr_sub_mod(limbs);
        } else {
            done = true;
        }
    }
    return limbs;
}

fn fr_pack48(a_mont: array<U64, 4>, dst_off: u32) {
    let a = fr_from_mont(a_mont);
    for (var i: u32 = 0u; i < 4u; i = i + 1u) {
        output[dst_off + i * 2u]      = a[i].lo;
        output[dst_off + i * 2u + 1u] = a[i].hi;
    }
    output[dst_off + 8u]  = 0u;
    output[dst_off + 9u]  = 0u;
    output[dst_off + 10u] = 0u;
    output[dst_off + 11u] = 0u;
}

@compute @workgroup_size(1, 1, 1)
fn kzg_blob_to_commit(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    if (i >= params.x) { return; }
    let blob_off = i * 32768u; // u32 words per blob
    let out_off  = i * 12u;

    var acc = array<U64, 4>(u64_zero(), u64_zero(), u64_zero(), u64_zero());
    for (var k: u32 = 0u; k < 4096u; k = k + 1u) {
        let x      = fr_from_be_blob(blob_off, k);
        let x_mont = fr_to_mont(x);
        acc        = fr_add(acc, x_mont);
    }
    fr_pack48(acc, out_off);
}

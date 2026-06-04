// WGSL peer of bls_fp_ops.h.metal — Fp arithmetic for BLS12-381.
// Limbs: 12 x u32 little-endian (no native u64 in WGSL).
// All values in Montgomery form. Layout matches blst's vec384 byte-for-byte
// (each pair of u32 makes one u64 limb of vec384, native endian).
//
// Concatenated into every WGSL pipeline by the host driver before kernel sources.

// BLS12-381 modulus p (12 x u32 LE).
const BLS_P: array<u32, 12> = array<u32, 12>(
    0xFFFFAAABu, 0xB9FEFFFFu, 0xB153FFFFu, 0x1EABFFFEu,
    0xF6B0F624u, 0x6730D2A0u, 0xF38512BFu, 0x64774B84u,
    0x434BACD7u, 0x4B1BA7B6u, 0x397FE69Au, 0x1A0111EAu
);

// R^2 mod p (Montgomery)
const BLS_R2: array<u32, 12> = array<u32, 12>(
    0x1C341746u, 0xF4DF1F34u, 0x09D104F1u, 0x0A76E6A6u,
    0x4C95B6D5u, 0x8DE5476Cu, 0x939D83C0u, 0x67EB88A9u,
    0xB519952Du, 0x9A793E85u, 0x92CAE3AAu, 0x11988FE5u
);

// R mod p (= 1 in Mont)
const BLS_R: array<u32, 12> = array<u32, 12>(
    0x0002FFFDu, 0x76090000u, 0xC40C0002u, 0xEBF40000u,
    0x53C758BAu, 0x5F489857u, 0x70525745u, 0x77CE5853u,
    0xA256EC6Du, 0x5C071A97u, 0xFA80E493u, 0x15F65EC3u
);

// p_inv (low 64 bits = 0x89F3FFFCFFFCFFFD)
const BLS_P_INV_LO: u32 = 0xFFFCFFFDu;
const BLS_P_INV_HI: u32 = 0x89F3FFFCu;

// 12 x u32 zero
const ZERO384: array<u32, 12> = array<u32, 12>(0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u);

fn u384_is_zero(a: array<u32, 12>) -> bool {
    var acc = 0u;
    for (var i = 0u; i < 12u; i = i + 1u) { acc = acc | a[i]; }
    return acc == 0u;
}

fn u384_cmp(a: array<u32, 12>, b: array<u32, 12>) -> i32 {
    for (var i = 11i; i >= 0; i = i - 1) {
        let ui = u32(i);
        if (a[ui] > b[ui]) { return 1; }
        if (a[ui] < b[ui]) { return -1; }
    }
    return 0;
}

// Add 12 x u32; returns final carry.
fn u384_add(a: array<u32, 12>, b: array<u32, 12>, r: ptr<function, array<u32, 12>>) -> u32 {
    var c: u32 = 0u;
    for (var i = 0u; i < 12u; i = i + 1u) {
        let s1 = a[i] + c;
        var c1: u32 = 0u; if (s1 < a[i]) { c1 = 1u; }
        let s2 = s1 + b[i];
        var c2: u32 = 0u; if (s2 < s1) { c2 = 1u; }
        (*r)[i] = s2;
        c = c1 + c2;
    }
    return c;
}

fn u384_sub(a: array<u32, 12>, b: array<u32, 12>, r: ptr<function, array<u32, 12>>) -> u32 {
    var bw: u32 = 0u;
    for (var i = 0u; i < 12u; i = i + 1u) {
        let d1 = a[i] - bw;
        var b1: u32 = 0u; if (d1 > a[i]) { b1 = 1u; }
        let d2 = d1 - b[i];
        var b2: u32 = 0u; if (d2 > d1) { b2 = 1u; }
        (*r)[i] = d2;
        bw = b1 + b2;
    }
    return bw;
}

// 32 x 32 -> 64 (lo, hi)
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

// 384x384 -> 768 schoolbook in u32.
fn u384_mul768(a: array<u32, 12>, b: array<u32, 12>, t: ptr<function, array<u32, 24>>) {
    for (var i = 0u; i < 24u; i = i + 1u) { (*t)[i] = 0u; }
    for (var i = 0u; i < 12u; i = i + 1u) {
        var carry: u32 = 0u;
        for (var j = 0u; j < 12u; j = j + 1u) {
            let prod = mul32_64(a[i], b[j]);
            let lo = prod.x;
            let hi = prod.y;

            // accumulate lo + carry + t[i+j]
            var s = lo + carry;
            var c1: u32 = 0u; if (s < lo) { c1 = 1u; }
            let s2 = s + (*t)[i + j];
            var c2: u32 = 0u; if (s2 < s) { c2 = 1u; }
            (*t)[i + j] = s2;
            carry = hi + c1 + c2;
        }
        // propagate final carry
        var k = i + 12u;
        while (carry != 0u && k < 24u) {
            let sum = (*t)[k] + carry;
            var c: u32 = 0u; if (sum < (*t)[k]) { c = 1u; }
            (*t)[k] = sum;
            carry = c;
            k = k + 1u;
        }
    }
}

// CIOS Montgomery reduce: t (24 x u32) -> r (12 x u32) = t * R^-1 mod p.
fn mont_reduce_384(t: ptr<function, array<u32, 24>>, r: ptr<function, array<u32, 12>>) {
    // a holds t plus an extra u32 for carry overflow at position 24.
    var a: array<u32, 26>;
    for (var i = 0u; i < 24u; i = i + 1u) { a[i] = (*t)[i]; }
    a[24] = 0u;
    a[25] = 0u;

    // We work in 32-bit limbs, so 6 reductions of 64-bit `u` from Metal become
    // 12 reductions of 32-bit `u`. p_inv_32 (low 32 bits of -p^-1 mod 2^32)
    // is BLS_P_INV_LO = 0xFFFCFFFDu.
    for (var i = 0u; i < 12u; i = i + 1u) {
        let u = a[i] * BLS_P_INV_LO;       // -a[i] * p^-1 mod 2^32
        var carry: u32 = 0u;
        for (var j = 0u; j < 12u; j = j + 1u) {
            let prod = mul32_64(u, BLS_P[j]);
            var s = prod.x + carry;
            var c1: u32 = 0u; if (s < prod.x) { c1 = 1u; }
            let s2 = s + a[i + j];
            var c2: u32 = 0u; if (s2 < s) { c2 = 1u; }
            a[i + j] = s2;
            carry = prod.y + c1 + c2;
        }
        // propagate
        var k = i + 12u;
        while (carry != 0u && k < 26u) {
            let sum = a[k] + carry;
            var c: u32 = 0u; if (sum < a[k]) { c = 1u; }
            a[k] = sum;
            carry = c;
            k = k + 1u;
        }
    }

    var rr: array<u32, 12>;
    for (var i = 0u; i < 12u; i = i + 1u) { rr[i] = a[12u + i]; }
    let cmp = u384_cmp(rr, BLS_P);
    if (a[24] != 0u || cmp >= 0) {
        var sub: array<u32, 12>;
        _ = u384_sub(rr, BLS_P, &sub);
        rr = sub;
    }
    *r = rr;
}

fn fp_mul(a: array<u32, 12>, b: array<u32, 12>) -> array<u32, 12> {
    var t: array<u32, 24>;
    u384_mul768(a, b, &t);
    var r: array<u32, 12>;
    mont_reduce_384(&t, &r);
    return r;
}

fn fp_sqr(a: array<u32, 12>) -> array<u32, 12> { return fp_mul(a, a); }

fn fp_add(a: array<u32, 12>, b: array<u32, 12>) -> array<u32, 12> {
    var r: array<u32, 12>;
    let c = u384_add(a, b, &r);
    let cmp = u384_cmp(r, BLS_P);
    if (c != 0u || cmp >= 0) {
        var s: array<u32, 12>;
        _ = u384_sub(r, BLS_P, &s);
        r = s;
    }
    return r;
}

fn fp_sub(a: array<u32, 12>, b: array<u32, 12>) -> array<u32, 12> {
    var r: array<u32, 12>;
    let bw = u384_sub(a, b, &r);
    if (bw != 0u) {
        var s: array<u32, 12>;
        _ = u384_add(r, BLS_P, &s);
        r = s;
    }
    return r;
}

fn fp_neg(a: array<u32, 12>) -> array<u32, 12> {
    if (u384_is_zero(a)) { return a; }
    var r: array<u32, 12>;
    _ = u384_sub(BLS_P, a, &r);
    return r;
}

// Fermat inversion: a^(p-2) mod p. Mirror Metal exactly.
// Note: we operate on 32-bit limbs; bit iteration is over 384 bits MSB->LSB.
fn fp_inv(a: array<u32, 12>) -> array<u32, 12> {
    var exp: array<u32, 12> = BLS_P;
    // exp -= 2 on the lowest limb (low limb is well above 2)
    exp[0] = exp[0] - 2u;

    var result: array<u32, 12> = BLS_R;       // 1 in Montgomery form
    var started: bool = false;
    for (var i = 11i; i >= 0; i = i - 1) {
        let ui = u32(i);
        for (var bit = 31i; bit >= 0; bit = bit - 1) {
            if (started) { result = fp_sqr(result); }
            let mask = 1u << u32(bit);
            if ((exp[ui] & mask) != 0u) {
                if (started) { result = fp_mul(result, a); }
                else { result = a; started = true; }
            }
        }
    }
    return result;
}

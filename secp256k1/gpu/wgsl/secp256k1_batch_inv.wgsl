// Montgomery batch inversion for secp256k1 -- WGSL port of
// secp256k1_batch_inv.metal. Output byte-equal to:
//   * cpp/batch_inv.hpp (CPU canonical body)
//   * gpu/metal/secp256k1_batch_inv.metal (Metal kernel)
//   * gpu/cuda/secp256k1_batch_inv.cu (CUDA kernel)
//
// WGSL has no native u64; each 64-bit limb is represented as two u32 halves
// stored little-endian (lo,hi) in storage. Inside the kernel we lift to a
// pair of u32 and implement 64x64->128 multiply via four 32x32->64 partials.
// This matches the carry sequence in mont_mul exactly.
//
// Single-thread workgroup keeps byte-equal determinism with the CPU body.

// 4 x u64 = 8 x u32. Layout: limbs[0].lo, limbs[0].hi, limbs[1].lo, limbs[1].hi, ...
struct U256 { w: array<u32, 8>; };

@group(0) @binding(0) var<storage, read>       in_buf:   array<U256>;
@group(0) @binding(1) var<storage, read_write> out_buf:  array<U256>;
@group(0) @binding(2) var<uniform>             cfg:      vec4<u32>;
// cfg.x = n, cfg.y = kind (0 = Fp, 1 = Fn)

// ---------- secp256k1 constants (limb little-endian, u32 halves) ----------

fn P_MOD() -> U256 {
    return U256(array<u32, 8>(
        0xFFFFFC2Fu, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu,
        0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
    ));
}
fn N_MOD() -> U256 {
    return U256(array<u32, 8>(
        0xD0364141u, 0xBFD25E8Cu, 0xAF48A03Bu, 0xBAAEDCE6u,
        0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
    ));
}
fn ONE_MONT_P() -> U256 {
    return U256(array<u32, 8>(
        0x000003D1u, 0x00000001u, 0u, 0u, 0u, 0u, 0u, 0u,
    ));
}
fn R2_N() -> U256 {
    return U256(array<u32, 8>(
        0x67D7D140u, 0x896CF214u, 0x0E7CF878u, 0x741496C2u,
        0x5BCD07C6u, 0xE697F5E4u, 0x81C69BC5u, 0x9D671CD5u,
    ));
}
fn ONE() -> U256 {
    return U256(array<u32, 8>(1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u));
}

// P_INV = 0xD838091DD2253531
fn P_INV_LO() -> u32 { return 0xD2253531u; }
fn P_INV_HI() -> u32 { return 0xD838091Du; }
// N_INV = 0x4B0DFF665588B13F
fn N_INV_LO() -> u32 { return 0x5588B13Fu; }
fn N_INV_HI() -> u32 { return 0x4B0DFF66u; }

// p - 2
fn P_M2() -> U256 {
    return U256(array<u32, 8>(
        0xFFFFFC2Du, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu,
        0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
    ));
}
// n - 2
fn N_M2() -> U256 {
    return U256(array<u32, 8>(
        0xD036413Fu, 0xBFD25E8Cu, 0xAF48A03Bu, 0xBAAEDCE6u,
        0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
    ));
}

// ---------- 64-bit limb load/store helpers ----------

struct U64 { lo: u32, hi: u32 };

fn limb(a: U256, i: u32) -> U64 {
    return U64(a.w[i * 2u], a.w[i * 2u + 1u]);
}
fn set_limb(a: ptr<function, U256>, i: u32, v: U64) {
    (*a).w[i * 2u]      = v.lo;
    (*a).w[i * 2u + 1u] = v.hi;
}

// ---------- 64-bit primitives ----------

fn u64_add(a: U64, b: U64) -> U64 {
    let lo = a.lo + b.lo;
    var carry: u32 = 0u;
    if (lo < a.lo) { carry = 1u; }
    let hi = a.hi + b.hi + carry;
    return U64(lo, hi);
}

// Returns (sum, carry-out) for a + b + cin
fn u64_addc(a: U64, b: U64, cin: u32) -> array<U64, 2> {
    let s1lo = a.lo + b.lo;
    var c1: u32 = 0u;
    if (s1lo < a.lo) { c1 = 1u; }
    let s1hi = a.hi + b.hi + c1;
    var co1: u32 = 0u;
    // detect overflow on hi: s1hi < a.hi (when c1 == 0) or s1hi <= a.hi (when c1 == 1)
    if (c1 == 0u) {
        if (s1hi < a.hi) { co1 = 1u; }
    } else {
        if (s1hi <= a.hi) { co1 = 1u; }
    }
    // add cin (a u64 with hi = 0)
    let s2lo = s1lo + cin;
    var c2: u32 = 0u;
    if (s2lo < s1lo) { c2 = 1u; }
    let s2hi = s1hi + c2;
    var co2: u32 = 0u;
    if (s2hi < s1hi) { co2 = 1u; }
    let co = co1 + co2;
    return array<U64, 2>(U64(s2lo, s2hi), U64(co, 0u));
}

// Returns (diff, borrow-out) for a - b - bin
fn u64_subb(a: U64, b: U64, bin: u32) -> array<U64, 2> {
    let d1lo = a.lo - b.lo;
    var br1: u32 = 0u;
    if (d1lo > a.lo) { br1 = 1u; }
    let d1hi = a.hi - b.hi - br1;
    var bo1: u32 = 0u;
    if (br1 == 0u) {
        if (d1hi > a.hi) { bo1 = 1u; }
    } else {
        if (d1hi >= a.hi) { bo1 = 1u; }
    }
    let d2lo = d1lo - bin;
    var br2: u32 = 0u;
    if (d2lo > d1lo) { br2 = 1u; }
    let d2hi = d1hi - br2;
    var bo2: u32 = 0u;
    if (d2hi > d1hi) { bo2 = 1u; }
    let bo = bo1 + bo2;
    return array<U64, 2>(U64(d2lo, d2hi), U64(bo, 0u));
}

// 64x64 -> (lo, hi) via four 32x32 partials.
fn mul64(a: U64, b: U64) -> array<U64, 2> {
    let al: u32 = a.lo;
    let ah: u32 = a.hi;
    let bl: u32 = b.lo;
    let bh: u32 = b.hi;

    // 32x32 helpers via splitting into 16-bit halves to stay within u32 ops.
    // We implement low * b, high * b separately and combine via 64-bit adds.
    // Easier: lift each pair to u64-via-(lo,hi) arithmetic.
    // ll = al * bl (64-bit)
    let ll = mul32(al, bl);
    // lh = al * bh
    let lh = mul32(al, bh);
    // hl = ah * bl
    let hl = mul32(ah, bl);
    // hh = ah * bh
    let hh = mul32(ah, bh);

    // mid = (ll >> 32) + (lh & 0xFFFFFFFF) + (hl & 0xFFFFFFFF)
    let ll_hi = U64(ll.hi, 0u);
    let lh_lo = U64(lh.lo, 0u);
    let hl_lo = U64(hl.lo, 0u);
    let mid1 = u64_add(ll_hi, lh_lo);
    let mid  = u64_add(mid1, hl_lo);

    // lo = (ll & 0xFFFFFFFF) | (mid << 32)
    let lo = U64(ll.lo, mid.lo);
    // hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32)
    let hh_full = hh;
    let lh_hi   = U64(lh.hi, 0u);
    let hl_hi   = U64(hl.hi, 0u);
    let mid_hi  = U64(mid.hi, 0u);
    let s1 = u64_add(hh_full, lh_hi);
    let s2 = u64_add(s1, hl_hi);
    let hi = u64_add(s2, mid_hi);

    return array<U64, 2>(lo, hi);
}

// 32x32 -> (lo, hi) packed as U64.
fn mul32(a: u32, b: u32) -> U64 {
    let alo = a & 0xFFFFu;
    let ahi = a >> 16u;
    let blo = b & 0xFFFFu;
    let bhi = b >> 16u;
    let p00 = alo * blo;
    let p01 = alo * bhi;
    let p10 = ahi * blo;
    let p11 = ahi * bhi;
    // p00 + ((p01 + p10) << 16) + (p11 << 32)
    let mid_a = p01 + (p00 >> 16u);
    var mid_carry: u32 = 0u;
    if (mid_a < p01) { mid_carry = 1u; }
    let mid_b = mid_a + p10;
    var mid_b_carry: u32 = 0u;
    if (mid_b < mid_a) { mid_b_carry = 1u; }
    let lo = (p00 & 0xFFFFu) | (mid_b << 16u);
    let hi = p11 + (mid_b >> 16u) + (mid_carry << 16u) + (mid_b_carry << 16u);
    return U64(lo, hi);
}

// 64-bit truncating multiply (lower 64 bits only).
fn mul64_lo(a: U64, b: U64) -> U64 {
    let prod = mul64(a, b);
    return prod[0];
}

// ---------- 256-bit subtraction ----------

fn u256_cmp(a: U256, b: U256) -> i32 {
    var i: i32 = 3;
    loop {
        if (i < 0) { break; }
        let ai = limb(a, u32(i));
        let bi = limb(b, u32(i));
        if (ai.hi < bi.hi) { return -1; }
        if (ai.hi > bi.hi) { return  1; }
        if (ai.lo < bi.lo) { return -1; }
        if (ai.lo > bi.lo) { return  1; }
        i = i - 1;
    }
    return 0;
}

fn sub_256(a: U256, b: U256) -> U256 {
    var r: U256;
    var br: u32 = 0u;
    for (var i: u32 = 0u; i < 4u; i = i + 1u) {
        let res = u64_subb(limb(a, i), limb(b, i), br);
        set_limb(&r, i, res[0]);
        br = res[1].lo;
    }
    return r;
}

// ---------- CIOS Montgomery multiplication ----------

fn mont_mul(a: U256, b: U256, m: U256, m_inv: U64) -> U256 {
    var t: array<U64, 6>;
    for (var k: u32 = 0u; k < 6u; k = k + 1u) { t[k] = U64(0u, 0u); }

    for (var i: u32 = 0u; i < 4u; i = i + 1u) {
        var carry = U64(0u, 0u);
        let bi = limb(b, i);
        for (var j: u32 = 0u; j < 4u; j = j + 1u) {
            let aj = limb(a, j);
            let prod = mul64(aj, bi);
            let lo = prod[0];
            let hi = prod[1];
            let sum1 = u64_addc(t[j], lo, 0u);
            let s1   = sum1[0];
            let c1   = sum1[1].lo;
            let sum2 = u64_addc(s1, carry, 0u);
            t[j]  = sum2[0];
            let c2 = sum2[1].lo;
            let new_carry_step = u64_addc(hi, U64(c1 + c2, 0u), 0u);
            carry = new_carry_step[0];
        }
        let s4 = u64_addc(t[4], carry, 0u);
        t[4]   = s4[0];
        t[5]   = u64_add(t[5], U64(s4[1].lo, 0u));

        let u = mul64_lo(t[0], m_inv);
        carry = U64(0u, 0u);
        for (var j: u32 = 0u; j < 4u; j = j + 1u) {
            let mj = limb(m, j);
            let prod = mul64(u, mj);
            let lo = prod[0];
            let hi = prod[1];
            let sum1 = u64_addc(t[j], lo, 0u);
            let s1 = sum1[0];
            let c1 = sum1[1].lo;
            let sum2 = u64_addc(s1, carry, 0u);
            t[j] = sum2[0];
            let c2 = sum2[1].lo;
            let new_carry_step = u64_addc(hi, U64(c1 + c2, 0u), 0u);
            carry = new_carry_step[0];
        }
        let s4b = u64_addc(t[4], carry, 0u);
        t[4]    = s4b[0];
        t[5]    = u64_add(t[5], U64(s4b[1].lo, 0u));

        // shift right by 64 bits (drop t[0])
        for (var j: u32 = 0u; j < 5u; j = j + 1u) { t[j] = t[j + 1u]; }
        t[5] = U64(0u, 0u);
    }

    var r: U256;
    set_limb(&r, 0u, t[0]);
    set_limb(&r, 1u, t[1]);
    set_limb(&r, 2u, t[2]);
    set_limb(&r, 3u, t[3]);

    let need_sub = (t[4].lo != 0u) || (t[4].hi != 0u) || (u256_cmp(r, m) >= 0);
    if (need_sub) {
        r = sub_256(r, m);
    }
    return r;
}

fn fp_mul(a: U256, b: U256) -> U256 { return mont_mul(a, b, P_MOD(), U64(P_INV_LO(), P_INV_HI())); }
fn fn_mul(a: U256, b: U256) -> U256 { return mont_mul(a, b, N_MOD(), U64(N_INV_LO(), N_INV_HI())); }
fn fp_sqr(a: U256)         -> U256 { return fp_mul(a, a); }
fn fn_sqr(a: U256)         -> U256 { return fn_mul(a, a); }

fn fp_pow(a: U256, e: U256) -> U256 {
    var result = ONE_MONT_P();
    var base = a;
    for (var lj: u32 = 0u; lj < 4u; lj = lj + 1u) {
        let w = limb(e, lj);
        // low half
        for (var bit: u32 = 0u; bit < 32u; bit = bit + 1u) {
            if (((w.lo >> bit) & 1u) != 0u) { result = fp_mul(result, base); }
            base = fp_sqr(base);
        }
        // high half
        for (var bit: u32 = 0u; bit < 32u; bit = bit + 1u) {
            if (((w.hi >> bit) & 1u) != 0u) { result = fp_mul(result, base); }
            base = fp_sqr(base);
        }
    }
    return result;
}
fn fp_inv(a: U256) -> U256 { return fp_pow(a, P_M2()); }

fn fn_pow(a: U256, e: U256) -> U256 {
    var result = mont_mul(ONE(), R2_N(), N_MOD(), U64(N_INV_LO(), N_INV_HI()));
    var base = a;
    for (var lj: u32 = 0u; lj < 4u; lj = lj + 1u) {
        let w = limb(e, lj);
        for (var bit: u32 = 0u; bit < 32u; bit = bit + 1u) {
            if (((w.lo >> bit) & 1u) != 0u) { result = fn_mul(result, base); }
            base = fn_sqr(base);
        }
        for (var bit: u32 = 0u; bit < 32u; bit = bit + 1u) {
            if (((w.hi >> bit) & 1u) != 0u) { result = fn_mul(result, base); }
            base = fn_sqr(base);
        }
    }
    return result;
}
fn fn_inv(a: U256) -> U256 { return fn_pow(a, N_M2()); }

// ---------- Batch inversion kernels (single-thread workgroup) ----------

@compute @workgroup_size(1)
fn secp256k1_batch_inv_fp(@builtin(global_invocation_id) gid: vec3<u32>) {
    if (gid.x != 0u) { return; }
    let n = cfg.x;
    if (n == 0u) { return; }

    out_buf[0] = in_buf[0];
    for (var i: u32 = 1u; i < n; i = i + 1u) {
        out_buf[i] = fp_mul(out_buf[i - 1u], in_buf[i]);
    }
    var inv = fp_inv(out_buf[n - 1u]);
    var k: u32 = n;
    loop {
        if (k <= 1u) { break; }
        let i = k - 1u;
        let t = fp_mul(inv, out_buf[i - 1u]);
        inv   = fp_mul(inv, in_buf[i]);
        out_buf[i] = t;
        k = k - 1u;
    }
    out_buf[0] = inv;
}

@compute @workgroup_size(1)
fn secp256k1_batch_inv_fn(@builtin(global_invocation_id) gid: vec3<u32>) {
    if (gid.x != 0u) { return; }
    let n = cfg.x;
    if (n == 0u) { return; }

    out_buf[0] = in_buf[0];
    for (var i: u32 = 1u; i < n; i = i + 1u) {
        out_buf[i] = fn_mul(out_buf[i - 1u], in_buf[i]);
    }
    var inv = fn_inv(out_buf[n - 1u]);
    var k: u32 = n;
    loop {
        if (k <= 1u) { break; }
        let i = k - 1u;
        let t = fn_mul(inv, out_buf[i - 1u]);
        inv   = fn_mul(inv, in_buf[i]);
        out_buf[i] = t;
        k = k - 1u;
    }
    out_buf[0] = inv;
}

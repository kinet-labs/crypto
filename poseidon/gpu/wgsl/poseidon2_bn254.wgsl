// First-party WGSL kernel for Poseidon2-BN254 (canonical default permutation).
//
// Mechanical port of poseidon/gpu/metal/poseidon2_bn254.metal -- byte-for-byte
// equivalent to kinet::crypto::poseidon::hash2 in poseidon/cpp/poseidon.cpp
// (gnark-crypto v0.20.1 ecc/bn254/fr/poseidon2 with t=2, rF=6, rP=50, d=5).
//
// WGSL has no native u64. Each 64-bit Montgomery limb is represented as a pair
// of u32 (lo, hi), and 64-bit ops are reconstructed from 32-bit primitives.
//
// The round-key constants come from poseidon2_bn254_rk.wgslh, which is emitted
// by the CPU body's dump_round_keys -> gen_gpu_constants. There is exactly one
// source of truth across CPU, Metal, CUDA, and WGSL.

// === BEGIN POSEIDON2_RK_LO/HI (auto-generated, prepended at compile time) ===
// In production, the host driver concatenates poseidon2_bn254_rk.wgslh in
// front of this file before submitting it to wgpu. The kernel body below
// references POSEIDON2_RK_LO[round][slot][limb] and POSEIDON2_RK_HI[...].
// === END POSEIDON2_RK_LO/HI ===

// =============================================================================
// 64-bit unsigned represented as (lo, hi) pair of u32.
// =============================================================================
struct U64 { lo: u32, hi: u32 };

fn u64_make(lo: u32, hi: u32) -> U64 {
    return U64(lo, hi);
}

fn u64_zero() -> U64 { return U64(0u, 0u); }

fn u64_lt(a: U64, b: U64) -> bool {
    if (a.hi != b.hi) { return a.hi < b.hi; }
    return a.lo < b.lo;
}

fn u64_eq(a: U64, b: U64) -> bool {
    return a.lo == b.lo && a.hi == b.hi;
}

// 64-bit add. Returns sum and carry-out (0 or 1).
fn u64_add(a: U64, b: U64) -> U64 {
    let lo = a.lo + b.lo;
    let c0: u32 = select(0u, 1u, lo < a.lo);
    let hi = a.hi + b.hi + c0;
    return U64(lo, hi);
}

// 64-bit add with carry. Returns sum; carry_out written via separate path.
struct U64Carry { v: U64, carry: u32 };

fn u64_add_carry(a: U64, b: U64, cin: u32) -> U64Carry {
    let lo1 = a.lo + b.lo;
    let c0: u32 = select(0u, 1u, lo1 < a.lo);
    let lo  = lo1 + cin;
    let c1: u32 = select(0u, 1u, lo < lo1);
    let hi1 = a.hi + b.hi;
    let c2: u32 = select(0u, 1u, hi1 < a.hi);
    let hi2 = hi1 + (c0 + c1);
    let c3: u32 = select(0u, 1u, hi2 < hi1);
    return U64Carry(U64(lo, hi2), c2 + c3);
}

// 64-bit sub with borrow. Returns difference; borrow_out via field.
struct U64Borrow { v: U64, borrow: u32 };

fn u64_sub_borrow(a: U64, b: U64, bin: u32) -> U64Borrow {
    let lo1: u32 = a.lo - b.lo;
    let bor0: u32 = select(0u, 1u, a.lo < b.lo);
    let lo: u32 = lo1 - bin;
    let bor1: u32 = select(0u, 1u, lo1 < bin);
    let hi1: u32 = a.hi - b.hi;
    let bor2: u32 = select(0u, 1u, a.hi < b.hi);
    let hi: u32 = hi1 - (bor0 + bor1);
    let bor3: u32 = select(0u, 1u, hi1 < (bor0 + bor1));
    return U64Borrow(U64(lo, hi), bor2 + bor3);
}

// 64x64 -> 128 multiply via four 32x32 -> 64 partial products.
struct U128 { l0: u32, l1: u32, l2: u32, l3: u32 };

fn umul64(a: U64, b: U64) -> U128 {
    // a = a.hi*2^32 + a.lo,  b = b.hi*2^32 + b.lo
    // a*b = a.lo*b.lo
    //     + (a.lo*b.hi + a.hi*b.lo) * 2^32
    //     + a.hi*b.hi * 2^64
    // Each 32x32 -> u64 product is decomposed into (lo, hi) u32.
    let p_ll: U64 = u64_make_from_u32_mul(a.lo, b.lo);
    let p_lh: U64 = u64_make_from_u32_mul(a.lo, b.hi);
    let p_hl: U64 = u64_make_from_u32_mul(a.hi, b.lo);
    let p_hh: U64 = u64_make_from_u32_mul(a.hi, b.hi);

    // word 0 = p_ll.lo
    let w0: u32 = p_ll.lo;
    // word 1 = p_ll.hi + p_lh.lo + p_hl.lo
    let s1a: u32 = p_ll.hi + p_lh.lo;
    let c1a: u32 = select(0u, 1u, s1a < p_ll.hi);
    let w1: u32  = s1a + p_hl.lo;
    let c1b: u32 = select(0u, 1u, w1 < s1a);
    let carry1: u32 = c1a + c1b;
    // word 2 = p_lh.hi + p_hl.hi + p_hh.lo + carry1
    let s2a: u32 = p_lh.hi + p_hl.hi;
    let c2a: u32 = select(0u, 1u, s2a < p_lh.hi);
    let s2b: u32 = s2a + p_hh.lo;
    let c2b: u32 = select(0u, 1u, s2b < s2a);
    let w2: u32  = s2b + carry1;
    let c2c: u32 = select(0u, 1u, w2 < s2b);
    let carry2: u32 = c2a + c2b + c2c;
    // word 3 = p_hh.hi + carry2
    let w3: u32 = p_hh.hi + carry2;

    return U128(w0, w1, w2, w3);
}

fn u64_make_from_u32_mul(a: u32, b: u32) -> U64 {
    // 32x32 -> 64 multiply. We split each operand into 16-bit halves to
    // avoid overflowing u32 in the partial products.
    let al: u32 = a & 0xffffu;
    let ah: u32 = a >> 16u;
    let bl: u32 = b & 0xffffu;
    let bh: u32 = b >> 16u;
    let ll: u32 = al * bl;          // up to 0xfffe0001
    let lh: u32 = al * bh;
    let hl: u32 = ah * bl;
    let hh: u32 = ah * bh;
    // mid = (ll >> 16) + (lh & 0xffff) + (hl & 0xffff)
    let mid_a: u32 = (ll >> 16u) + (lh & 0xffffu);
    let mid_b: u32 = mid_a + (hl & 0xffffu);
    let mid_carry: u32 = (mid_b >> 16u);  // overflow into hi
    let lo: u32 = (ll & 0xffffu) | (mid_b << 16u);
    let hi: u32 = hh + (lh >> 16u) + (hl >> 16u) + mid_carry;
    return U64(lo, hi);
}

// 64-bit u64 product of two U64; returns the low 64 bits only (used for
// computing m = t[0] * Q_INV_NEG mod 2^64).
fn u64_mul_low(a: U64, b: U64) -> U64 {
    let p_ll: U64 = u64_make_from_u32_mul(a.lo, b.lo);
    let p_lh: U64 = u64_make_from_u32_mul(a.lo, b.hi);
    let p_hl: U64 = u64_make_from_u32_mul(a.hi, b.lo);
    let lo: u32 = p_ll.lo;
    let hi: u32 = p_ll.hi + p_lh.lo + p_hl.lo;
    return U64(lo, hi);
}

// =============================================================================
// BN254 Fr modulus + Montgomery params (Q_INV_NEG, R_SQUARE).
// Each constant declared as (lo, hi) u32 pair.
// =============================================================================
const Q0_LO: u32 = 0xf0000001u; const Q0_HI: u32 = 0x43e1f593u;
const Q1_LO: u32 = 0x79b97091u; const Q1_HI: u32 = 0x2833e848u;
const Q2_LO: u32 = 0x8181585du; const Q2_HI: u32 = 0xb85045b6u;
const Q3_LO: u32 = 0xe131a029u; const Q3_HI: u32 = 0x30644e72u;
const QINV_LO: u32 = 0xefffffffu; const QINV_HI: u32 = 0xc2e1f593u;

// R^2 mod q, Montgomery form.
//   1997599621687373223  = 0x1bb8e645ae216da7
//   6052339484930628067  = 0x53fe3ab1e35c59e3
//   10108755138030829701 = 0x8c49833d53bb8085
//   150537098327114917   = 0x0216d0b17f4e44a5
const R2_0_LO: u32 = 0xae216da7u; const R2_0_HI: u32 = 0x1bb8e645u;
const R2_1_LO: u32 = 0xe35c59e3u; const R2_1_HI: u32 = 0x53fe3ab1u;
const R2_2_LO: u32 = 0x53bb8085u; const R2_2_HI: u32 = 0x8c49833du;
const R2_3_LO: u32 = 0x7f4e44a5u; const R2_3_HI: u32 = 0x0216d0b1u;

// =============================================================================
// 256-bit Fr in Montgomery form, four U64 limbs.
// =============================================================================
struct Fr {
    l0: U64,
    l1: U64,
    l2: U64,
    l3: U64,
};

fn fr_zero() -> Fr {
    return Fr(u64_zero(), u64_zero(), u64_zero(), u64_zero());
}

fn fr_q() -> Fr {
    return Fr(U64(Q0_LO, Q0_HI), U64(Q1_LO, Q1_HI),
              U64(Q2_LO, Q2_HI), U64(Q3_LO, Q3_HI));
}

fn fr_r2() -> Fr {
    return Fr(U64(R2_0_LO, R2_0_HI), U64(R2_1_LO, R2_1_HI),
              U64(R2_2_LO, R2_2_HI), U64(R2_3_LO, R2_3_HI));
}

fn cmp_q(a: Fr) -> i32 {
    let q = fr_q();
    if (!u64_eq(a.l3, q.l3)) {
        if (u64_lt(a.l3, q.l3)) { return -1; } else { return 1; }
    }
    if (!u64_eq(a.l2, q.l2)) {
        if (u64_lt(a.l2, q.l2)) { return -1; } else { return 1; }
    }
    if (!u64_eq(a.l1, q.l1)) {
        if (u64_lt(a.l1, q.l1)) { return -1; } else { return 1; }
    }
    if (!u64_eq(a.l0, q.l0)) {
        if (u64_lt(a.l0, q.l0)) { return -1; } else { return 1; }
    }
    return 0;
}

fn fr_sub_q(a: Fr) -> Fr {
    let q = fr_q();
    let r0 = u64_sub_borrow(a.l0, q.l0, 0u);
    let r1 = u64_sub_borrow(a.l1, q.l1, r0.borrow);
    let r2 = u64_sub_borrow(a.l2, q.l2, r1.borrow);
    let r3 = u64_sub_borrow(a.l3, q.l3, r2.borrow);
    return Fr(r0.v, r1.v, r2.v, r3.v);
}

fn reduce_once(a: Fr) -> Fr {
    if (cmp_q(a) >= 0) { return fr_sub_q(a); }
    return a;
}

fn fr_add(a: Fr, b: Fr) -> Fr {
    let r0 = u64_add_carry(a.l0, b.l0, 0u);
    let r1 = u64_add_carry(a.l1, b.l1, r0.carry);
    let r2 = u64_add_carry(a.l2, b.l2, r1.carry);
    let r3 = u64_add_carry(a.l3, b.l3, r2.carry);
    var c = Fr(r0.v, r1.v, r2.v, r3.v);
    if (r3.carry != 0u || cmp_q(c) >= 0) {
        c = fr_sub_q(c);
    }
    return c;
}

fn fr_double(a: Fr) -> Fr { return fr_add(a, a); }

// CIOS Montgomery multiplication. Bit-identical algorithm to the CPU body.
fn fr_mul(a: Fr, b: Fr) -> Fr {
    var t0 = u64_zero();
    var t1 = u64_zero();
    var t2 = u64_zero();
    var t3 = u64_zero();
    var t4 = u64_zero();
    let al = array<U64, 4>(a.l0, a.l1, a.l2, a.l3);
    let bl = array<U64, 4>(b.l0, b.l1, b.l2, b.l3);
    let qq = array<U64, 4>(U64(Q0_LO, Q0_HI), U64(Q1_LO, Q1_HI),
                            U64(Q2_LO, Q2_HI), U64(Q3_LO, Q3_HI));
    let qinv = U64(QINV_LO, QINV_HI);

    for (var i: i32 = 0; i < 4; i = i + 1) {
        // t += a * b[i]
        var cy: U64 = u64_zero();
        for (var j: i32 = 0; j < 4; j = j + 1) {
            let prod: U128 = umul64(al[j], bl[i]);
            let lo: U64 = U64(prod.l0, prod.l1);
            let hi: U64 = U64(prod.l2, prod.l3);
            // Pick t[j]
            var tj: U64 = u64_zero();
            if (j == 0) { tj = t0; }
            else if (j == 1) { tj = t1; }
            else if (j == 2) { tj = t2; }
            else { tj = t3; }
            let s = u64_add_carry(tj, lo, 0u);
            let s2 = u64_add_carry(s.v, cy, 0u);
            // Update t[j]
            if (j == 0) { t0 = s2.v; }
            else if (j == 1) { t1 = s2.v; }
            else if (j == 2) { t2 = s2.v; }
            else { t3 = s2.v; }
            // cy = hi + s.carry + s2.carry
            let cy1 = u64_add_carry(hi, U64(s.carry, 0u), 0u);
            let cy2 = u64_add_carry(cy1.v, U64(s2.carry, 0u), 0u);
            cy = cy2.v;
        }
        // t[4] += cy
        let t4u = u64_add_carry(t4, cy, 0u);
        t4 = t4u.v;

        // m = t[0] * qInvNeg mod 2^64
        let m: U64 = u64_mul_low(t0, qinv);

        // t += m * q
        cy = u64_zero();
        for (var j: i32 = 0; j < 4; j = j + 1) {
            let prod = umul64(m, qq[j]);
            let lo: U64 = U64(prod.l0, prod.l1);
            let hi: U64 = U64(prod.l2, prod.l3);
            var tj: U64 = u64_zero();
            if (j == 0) { tj = t0; }
            else if (j == 1) { tj = t1; }
            else if (j == 2) { tj = t2; }
            else { tj = t3; }
            let s = u64_add_carry(tj, lo, 0u);
            let s2 = u64_add_carry(s.v, cy, 0u);
            if (j == 0) { t0 = s2.v; }
            else if (j == 1) { t1 = s2.v; }
            else if (j == 2) { t2 = s2.v; }
            else { t3 = s2.v; }
            let cy1 = u64_add_carry(hi, U64(s.carry, 0u), 0u);
            let cy2 = u64_add_carry(cy1.v, U64(s2.carry, 0u), 0u);
            cy = cy2.v;
        }
        let t4u2 = u64_add_carry(t4, cy, 0u);
        t4 = t4u2.v;

        // Shift right by one limb.
        t0 = t1;
        t1 = t2;
        t2 = t3;
        t3 = t4;
        t4 = u64_zero();
    }
    var c = Fr(t0, t1, t2, t3);
    c = reduce_once(c);
    return c;
}

fn fr_square(a: Fr) -> Fr { return fr_mul(a, a); }

// =============================================================================
// Poseidon2-BN254 default permutation.
// =============================================================================

fn sbox(x: Fr) -> Fr {
    let x2 = fr_square(x);
    let x4 = fr_square(x2);
    return fr_mul(x4, x);
}

struct State2 { s0: Fr, s1: Fr };

fn mat_mul_external(s: State2) -> State2 {
    let tmp = fr_add(s.s0, s.s1);
    return State2(fr_add(s.s0, tmp), fr_add(s.s1, tmp));
}

fn mat_mul_internal(s: State2) -> State2 {
    let sum = fr_add(s.s0, s.s1);
    let s0p = fr_add(s.s0, sum);
    let s1d = fr_double(s.s1);
    let s1p = fr_add(s1d, sum);
    return State2(s0p, s1p);
}

const FULL_HALF: i32 = 3;
const PARTIAL: i32   = 50;

fn load_rk(round: i32, slot: i32) -> Fr {
    return Fr(
        U64(POSEIDON2_RK_LO[round][slot][0], POSEIDON2_RK_HI[round][slot][0]),
        U64(POSEIDON2_RK_LO[round][slot][1], POSEIDON2_RK_HI[round][slot][1]),
        U64(POSEIDON2_RK_LO[round][slot][2], POSEIDON2_RK_HI[round][slot][2]),
        U64(POSEIDON2_RK_LO[round][slot][3], POSEIDON2_RK_HI[round][slot][3])
    );
}

fn permute(s_in: State2) -> State2 {
    var s = mat_mul_external(s_in);
    for (var i: i32 = 0; i < FULL_HALF; i = i + 1) {
        let k0 = load_rk(i, 0);
        let k1 = load_rk(i, 1);
        s.s0 = fr_add(s.s0, k0);
        s.s1 = fr_add(s.s1, k1);
        s.s0 = sbox(s.s0);
        s.s1 = sbox(s.s1);
        s = mat_mul_external(s);
    }
    for (var i: i32 = 0; i < PARTIAL; i = i + 1) {
        let k0 = load_rk(FULL_HALF + i, 0);
        s.s0 = fr_add(s.s0, k0);
        s.s0 = sbox(s.s0);
        s = mat_mul_internal(s);
    }
    for (var i: i32 = 0; i < FULL_HALF; i = i + 1) {
        let k0 = load_rk(FULL_HALF + PARTIAL + i, 0);
        let k1 = load_rk(FULL_HALF + PARTIAL + i, 1);
        s.s0 = fr_add(s.s0, k0);
        s.s1 = fr_add(s.s1, k1);
        s.s0 = sbox(s.s0);
        s.s1 = sbox(s.s1);
        s = mat_mul_external(s);
    }
    return s;
}

// =============================================================================
// Bytes (BE) <-> Fr conversions, Montgomery form on the inside.
// =============================================================================

fn read_be64(buf: ptr<storage, array<u32>, read>, byte_off: u32) -> U64 {
    // Read 8 bytes big-endian into a U64. WGSL storage buffers are word-
    // addressable, so we unpack from u32 words.
    let w0 = (*buf)[byte_off / 4u];
    let w1 = (*buf)[byte_off / 4u + 1u];
    // be: bytes [b0 b1 b2 b3 b4 b5 b6 b7] -> u64 = b0<<56 | ... | b7
    // Little-endian u32 word holds bytes [w&0xff, (w>>8)&0xff, ..., (w>>24)&0xff]
    // at increasing byte addresses.
    let b0: u32 = (w0      ) & 0xffu;
    let b1: u32 = (w0 >>  8u) & 0xffu;
    let b2: u32 = (w0 >> 16u) & 0xffu;
    let b3: u32 = (w0 >> 24u) & 0xffu;
    let b4: u32 = (w1      ) & 0xffu;
    let b5: u32 = (w1 >>  8u) & 0xffu;
    let b6: u32 = (w1 >> 16u) & 0xffu;
    let b7: u32 = (w1 >> 24u) & 0xffu;
    let hi: u32 = (b0 << 24u) | (b1 << 16u) | (b2 << 8u) | b3;
    let lo: u32 = (b4 << 24u) | (b5 << 16u) | (b6 << 8u) | b7;
    return U64(lo, hi);
}

fn be_to_fr_mont(buf: ptr<storage, array<u32>, read>, off: u32) -> Fr {
    var x = Fr(read_be64(buf, off + 24u),
               read_be64(buf, off + 16u),
               read_be64(buf, off +  8u),
               read_be64(buf, off       ));
    for (var i: i32 = 0; i < 4; i = i + 1) {
        if (cmp_q(x) < 0) { break; }
        x = fr_sub_q(x);
    }
    return fr_mul(x, fr_r2());
}

fn write_be64(buf: ptr<storage, array<u32>, read_write>, byte_off: u32, v: U64) {
    // BE bytes: [hi>>24, hi>>16, hi>>8, hi, lo>>24, lo>>16, lo>>8, lo]
    let b0: u32 = (v.hi >> 24u) & 0xffu;
    let b1: u32 = (v.hi >> 16u) & 0xffu;
    let b2: u32 = (v.hi >>  8u) & 0xffu;
    let b3: u32 =  v.hi         & 0xffu;
    let b4: u32 = (v.lo >> 24u) & 0xffu;
    let b5: u32 = (v.lo >> 16u) & 0xffu;
    let b6: u32 = (v.lo >>  8u) & 0xffu;
    let b7: u32 =  v.lo         & 0xffu;
    let w0: u32 = b0 | (b1 << 8u) | (b2 << 16u) | (b3 << 24u);
    let w1: u32 = b4 | (b5 << 8u) | (b6 << 16u) | (b7 << 24u);
    (*buf)[byte_off / 4u]      = w0;
    (*buf)[byte_off / 4u + 1u] = w1;
}

fn fr_mont_to_be(buf: ptr<storage, array<u32>, read_write>, off: u32, x: Fr) {
    let one_reg = Fr(U64(1u, 0u), U64(0u, 0u), U64(0u, 0u), U64(0u, 0u));
    let r = fr_mul(x, one_reg);
    write_be64(buf, off + 0u,  r.l3);
    write_be64(buf, off + 8u,  r.l2);
    write_be64(buf, off + 16u, r.l1);
    write_be64(buf, off + 24u, r.l0);
}

// =============================================================================
// Storage bindings + kernel.
// =============================================================================
@group(0) @binding(0) var<storage, read>       g_pairs: array<u32>;   // n*64 bytes
@group(0) @binding(1) var<storage, read_write> g_outs:  array<u32>;   // n*32 bytes
@group(0) @binding(2) var<uniform>             g_n:     u32;

@compute @workgroup_size(64)
fn poseidon2_hash2_batch(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i: u32 = gid.x;
    if (i >= g_n) { return; }
    let in_off:  u32 = i * 64u;
    let out_off: u32 = i * 32u;
    var s = State2(be_to_fr_mont(&g_pairs, in_off),
                    be_to_fr_mont(&g_pairs, in_off + 32u));
    let saved_right = s.s1;
    s = permute(s);
    let digest = fr_add(saved_right, s.s1);
    fr_mont_to_be(&g_outs, out_off, digest);
}
